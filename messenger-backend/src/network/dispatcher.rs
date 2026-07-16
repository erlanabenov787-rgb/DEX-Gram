//! Диспетчер входящих пакетов. Разбирает Packet по типу и вызывает нужный обработчик.
//! Здесь происходит вся "магия" — onion peeling, ratchet decrypt, mailbox и т.д.

use crate::network::mailbox::MailboxService;
use crate::network::onion::{peel_layer, wrap_layers, OnionPacket, PeelResult};
use crate::network::{mailbox, relay, IncomingSender, OutboundSender};
use crate::protocol::{Packet, PacketType};
use crate::session::manager::SessionManager;
use crate::types::DestinationHint;
use anyhow::Result;
use tracing::{info, warn};

/// Домен-разделитель для подписи MAILBOX_FETCH-запросов (см.
/// SessionManager::sign_own_bytes/verify_own_bytes и fetch_mailbox/
/// handle_mailbox_fetch ниже). Отдельная константа, а не голая строка
/// на обоих концах, чтобы опечатка в одном месте не тихо сломала
/// проверку на другом.
const MAILBOX_FETCH_SIGNATURE_DOMAIN: &[u8] = b"MAILBOX_FETCH_V1:";

/// Главная точка входа для всех входящих Packet (из p2p или из relay).
///
/// Примечание: SessionManager использует RwLock внутри, поэтому здесь
/// достаточно `&SessionManager` (без `&mut`) — это также позволяет
/// вызывать эту функцию из p2p.rs, где `self.session_manager` не может
/// быть заимствован как `&mut` одновременно с `&mut self.swarm`.
///
/// Возвращает `Ok(Some(response))`, если для этого пакета нужен
/// содержательный ответ поверх request_response (сейчас только
/// MAILBOX_FETCH — см. handle_mailbox_fetch ниже); `Ok(None)` для всех
/// остальных типов, тогда p2p.rs сам шлёт стандартный пустой ack.
/// РАНЬШЕ эта функция всегда возвращала `()`, а p2p.rs слал один и тот
/// же пустой ack-Packet независимо от типа входящего пакета — из-за
/// этого MAILBOX_FETCH физически не мог вернуть запрашиваемые
/// сообщения, даже если бы сам процесс их нашёл в mailbox.
pub async fn handle_incoming_packet(
    packet: Packet,
    session_manager: &SessionManager,
    our_onion_secret: &x25519_dalek::StaticSecret, // Приватный onion-ключ этого relay (если мы relay)
    mailbox_service: &MailboxService,
    outbound: &OutboundSender,
    incoming: &IncomingSender,
) -> Result<Option<Packet>> {
    match PacketType::try_from(packet.r#type).unwrap_or(PacketType::Unknown) {
        PacketType::DirectMessage | PacketType::RelayForward => {
            // Это может быть onion-пакет (для нас как relay) или уже inner после peeling
            handle_onion_or_direct(packet, session_manager, our_onion_secret, mailbox_service, outbound, incoming)
                .await?;
            Ok(None)
        }
        PacketType::MailboxFetch => {
            Ok(Some(handle_mailbox_fetch(packet, session_manager, mailbox_service).await?))
        }
        PacketType::MailboxStore => {
            // ЧЕСТНО: прямой MAILBOX_STORE (не через onion) сейчас никем
            // не отправляется — единственный реализованный путь доставки
            // в mailbox — onion exit (см. handle_onion_or_direct ->
            // DestinationHint::Mailbox выше). Если в будущем понадобится
            // прямой (не-onion) store, потребуется то же самое
            // recipient_user_id-поле, что уже добавлено в Packet ради
            // MAILBOX_FETCH.
            warn!("MAILBOX_STORE напрямую (не через onion exit) пока не реализован");
            Ok(None)
        }
        PacketType::DhtAnnounce => {
            // MVP-комментарий: Packet-based DHT announce не нужен —
            // каждый узел публикует DhtRecord/PreKeyBundle сам через
            // libp2p Kademlia API (NodeHandle::publish_my_record /
            // publish_my_prekey_bundle, периодически через
            // NodeCommand::RepublishDht из services/background.rs).
            // Packet-based announce потребовался бы для proxy-publish
            // (relay публикует запись от имени оффлайн-клиента) —
            // это Phase 4 фича, не MVP.
            info!("DhtAnnounce Packet получен (Packet-based DHT announce не реализован — используется Kademlia API напрямую)");
            Ok(None)
        }
        PacketType::DhtLookup => {
            // Аналогично: Packet-based lookup не нужен для MVP —
            // прямой Kademlia get_record вызывается через
            // NodeHandle::lookup_user (p2p.rs) и возвращает результат
            // через oneshot-канал в handle_kademlia_event.
            // Packet-based lookup потребовался бы для клиентов
            // без libp2p-стека (мобильный HTTP relay-прокси — Phase 4).
            tracing::debug!("DhtLookup Packet получен (Packet-based DHT lookup не реализован — используется Kademlia API напрямую)");
            Ok(None)
        }
        PacketType::DummyTraffic => {
            // Метаданные-защита — просто игнорируем, но логируем для статистики
            tracing::trace!("Dummy traffic packet received (good for metadata protection)");
            Ok(None)
        }
        _ => {
            warn!("Неизвестный/неподдерживаемый тип пакета: {:?}", packet.r#type);
            Ok(None)
        }
    }
}

/// Обрабатывает MAILBOX_FETCH: `packet.recipient_user_id` — чей mailbox
/// запрашивают, `packet.sender_signature` — подпись запрашивающего над
/// `MAILBOX_FETCH_SIGNATURE_DOMAIN || recipient_user_id`, доказывающая
/// что он реально владеет этим UserID (иначе relay отдал бы чужой
/// mailbox любому, кто просто напишет чужой UserID в поле).
///
/// ЧЕСТНО про replay: сообщение о том же запросе можно переслать этому
/// же relay повторно (сигнатура не привязана к nonce/времени) — но это
/// не даёт атакующему ничего сверх того, что он уже видел (тот же набор
/// пока ещё не забранных сообщений того же владельца), поэтому для MVP
/// принято как некритичный trade-off, а не молча притворяемся, что
/// replay-защиты нет вообще.
///
/// ЧЕСТНО про atomicity: fetch_pending + acknowledge_delivered — две
/// отдельные операции (см. MailboxService), не одна транзакция. Если
/// процесс упадёт между ними, сообщения останутся в mailbox и будут
/// отданы повторно при следующем fetch — то есть возможен дубликат
/// доставки, но не потеря сообщения. Это тот же trade-off, что уже был
/// явно задокументирован в MailboxService::fetch_pending/store_message.
async fn handle_mailbox_fetch(
    packet: Packet,
    session_manager: &SessionManager,
    mailbox_service: &MailboxService,
) -> Result<Packet> {
    let owner = packet.recipient_user_id.clone();
    if owner.is_empty() {
        anyhow::bail!("MAILBOX_FETCH без recipient_user_id");
    }

    let mut signed_bytes = MAILBOX_FETCH_SIGNATURE_DOMAIN.to_vec();
    signed_bytes.extend_from_slice(owner.as_bytes());
    let signature_ok = session_manager
        .verify_own_bytes(&owner, &signed_bytes, &packet.sender_signature)
        .await
        .unwrap_or(false);
    if !signature_ok {
        anyhow::bail!(
            "MAILBOX_FETCH для {owner}: подпись не прошла проверку (не владелец UserID или его \
             identity-ключ не найден через PeerIdentitySource)"
        );
    }

    let pending = mailbox_service.fetch_pending(&owner).await?;
    info!("MAILBOX_FETCH: отдаю {} сообщений владельцу {owner}", pending.len());
    // Отдали клиенту — считаем доставленным сразу (см. честную оговорку
    // про atomicity в комментарии функции выше).
    mailbox_service.acknowledge_delivered(&owner).await?;

    let payload = bincode::serialize(&pending)
        .map_err(|e| anyhow::anyhow!("не удалось сериализовать ответ MAILBOX_FETCH: {e}"))?;

    Ok(Packet {
        protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
        r#type: PacketType::MailboxFetch.into(),
        encrypted_payload: payload,
        sender_signature: Vec::new(),
        padding_len: 0,
        recipient_user_id: String::new(),
    })
}

/// Строит и отправляет MAILBOX_FETCH-запрос конкретному relay-узлу за
/// нашими собственными оффлайн-сообщениями. Вызывается периодически из
/// services/background.rs (через NodeCommand::FetchMailbox, т.к. сам
/// NodeHandle заперт внутри node.run()/run_with_commands() — тот же
/// паттерн, что и send_message ниже вызывается через NodeCommand::SendText).
///
/// Результат приходит не отсюда, а асинхронно через request_response
/// Response — см. обработку `Event::Message::Response` в p2p.rs, где
/// пришедшие сообщения расшифровываются и уходят в incoming_tx, тем же
/// путём что обычные DirectMessage.
pub async fn fetch_mailbox(
    node: &mut crate::network::p2p::NodeHandle,
    relay_id: &str,
) -> anyhow::Result<()> {
    let my_user_id = node.session_manager.my_user_id().clone();
    let mut signed_bytes = MAILBOX_FETCH_SIGNATURE_DOMAIN.to_vec();
    signed_bytes.extend_from_slice(my_user_id.as_bytes());
    let signature = node.session_manager.sign_own_bytes(&signed_bytes);

    let request = Packet {
        protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
        r#type: PacketType::MailboxFetch.into(),
        encrypted_payload: Vec::new(),
        sender_signature: signature,
        padding_len: 0,
        recipient_user_id: my_user_id,
    };

    info!("Отправляю MAILBOX_FETCH на relay {relay_id}");
    node.send_packet(relay_id, request).await
}

/// Реальная отправка зашифрованного сообщения: X3DH/ratchet-шифрование
/// (через SessionManager) + реальное onion-заворачивание в N слоёв
/// (через relay_scoring + onion::wrap_layers) перед тем как пакет
/// физически уйдёт первому хопу цепочки.
///
/// ВАЖНО (см. config::StaticRelay): выбор хопов сейчас идёт по
/// статичному списку из конфига, а не по DHT — нужно минимум 3
/// сконфигурированных relay, иначе `select_hops` вернёт ошибку
/// "недостаточно known relays".
pub async fn send_message(
    node: &mut crate::network::p2p::NodeHandle,
    target_user_id: &str,
    plaintext: &[u8],
) -> anyhow::Result<()> {
    // TODO (Phase 3): Добавить DHT lookup UserID -> PeerId перед отправкой.
    // Сейчас target_user_id используется и как UserID (для шифрования),
    // и как ключ mailbox на exit-узле — этого достаточно для MVP, где
    // получатель тот же UserID использует для обеих ролей.
    let peer: crate::identity::UserId = target_user_id.to_string();
    let envelope_packet = node.session_manager.encrypt_message(&peer, plaintext).await?;
    let envelope_bytes = bincode::serialize(&envelope_packet)?;

    let hop_count = crate::constants::ONION_MIN_HOPS;
    let destination = DestinationHint::Mailbox(peer.clone());

    // Если знаем mailbox_candidates получателя (закешировались из DHT-lookup-а,
    // который происходит при первом X3DH), форсируем exit-хоп на один из его
    // опубликованных relay — иначе сообщение может осесть на relay, который
    // получатель никогда не опрашивает через fetch_mailbox (gap 4/5).
    // Промежуточные хопы выбираем независимо из scoring-базы.
    // Fallback (warn) — когда DHT lookup ещё не завершился или получатель
    // не опубликовал кандидатов вообще; в этом случае exit выбирается
    // случайно из наших known relays, как было раньше.
    let (hops, first_hop) = if let Some(candidates) = node.known_mailbox_candidates.get(&peer).cloned() {
        let exit_hop = node.relay_scoring.select_exit_from(&candidates).await?;
        let intermediate_count = hop_count.saturating_sub(1);
        let mut circuit_hops = if intermediate_count > 0 {
            node.relay_scoring.select_hops(intermediate_count).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let first = circuit_hops.first().map(|h| h.relay_id.clone())
            .unwrap_or_else(|| exit_hop.relay_id.clone());
        circuit_hops.push(exit_hop);
        (circuit_hops, first)
    } else {
        warn!(
            "Mailbox candidates для {} не закешированы (DHT lookup ещё не завершился или \
             получатель не опубликовал кандидатов) — exit-хоп выбирается из наших known \
             relays без гарантии совпадения с mailbox получателя",
            peer
        );
        let all_hops = node.relay_scoring.select_hops(hop_count).await?;
        let first = all_hops[0].relay_id.clone();
        (all_hops, first)
    };

    let mut circuit = crate::network::onion::build_circuit(hops, destination)?;
    let onion_packet = wrap_layers(&mut circuit, envelope_bytes)?;

    let transport_packet = crate::protocol::Packet {
        protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
        r#type: crate::protocol::PacketType::RelayForward.into(),
        encrypted_payload: onion_packet.layers,
        sender_signature: Vec::new(),
        padding_len: 0,
        recipient_user_id: String::new(),
    };

    info!("Sending onion-wrapped message via first hop {}", first_hop);
    node.send_packet(&first_hop, transport_packet).await
}

/// Отправляет DummyTraffic-пакет конкретному relay для защиты метаданных.
/// Случайный размер payload (64–512 байт) гарантирует, что dummy-пакеты
/// не отличимы от реальных по размеру — наблюдатель видит только шум.
/// Вызывается через NodeCommand::SendDummy из handle_command (p2p.rs).
pub async fn send_dummy_packet(
    node: &mut crate::network::p2p::NodeHandle,
    relay_id: &str,
) -> anyhow::Result<()> {
    // Случайный размер в диапазоне 64–512 байт чтобы не создавать
    // статистически отличимую сигнатуру по длине пакета.
    let padding_size: usize = (rand::random::<u8>() as usize) % 449 + 64;
    let dummy_payload: Vec<u8> = (0..padding_size).map(|_| rand::random::<u8>()).collect();

    let packet = crate::protocol::Packet {
        protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
        r#type: crate::protocol::PacketType::DummyTraffic.into(),
        encrypted_payload: dummy_payload,
        sender_signature: Vec::new(),
        padding_len: padding_size as u32,
        recipient_user_id: String::new(),
    };

    tracing::trace!("Dummy трафик → relay {relay_id} ({padding_size} bytes)");
    node.send_packet(relay_id, packet).await
}

/// Обрабатывает как обычный DirectMessage, так и RelayForward (onion).
async fn handle_onion_or_direct(
    packet: Packet,
    session_manager: &SessionManager,
    our_onion_secret: &x25519_dalek::StaticSecret,
    mailbox_service: &MailboxService,
    outbound: &OutboundSender,
    incoming: &IncomingSender,
) -> Result<()> {
    // Пытаемся снять onion слой (если это relay-узел)
    let onion_packet = OnionPacket { layers: packet.encrypted_payload.clone() };

    match peel_layer(&onion_packet, our_onion_secret) {
        Ok(PeelResult::Forward { next_hop, remaining }) => {
            info!("Onion: forwarding to next hop {}", next_hop);
            relay::service::forward_to_next_hop(next_hop, remaining, outbound).await?;
        }
        Ok(PeelResult::Exit { payload, destination }) => {
            info!("Onion: reached exit, destination = {:?}", destination);
            match destination {
                DestinationHint::Mailbox(user_id) => {
                    mailbox::service::store_for_user(mailbox_service, &user_id, payload).await?;
                }
                DestinationHint::DirectPeer(peer) => {
                    // TODO: пока онион-exit поддерживает только Mailbox
                    // (см. send_message выше — мы всегда строим Mailbox).
                    // Прямая доставка "живому" P2P-соединению потребует
                    // отдельного протокольного шага (например, ACK через
                    // outbound-канал), не делаю этого молча.
                    tracing::debug!("Direct delivery to {:?} requested but not implemented yet", peer);
                }
            }
        }
        Err(_) => {
            // Не удалось снять слой — возможно это DirectMessage для конечного получателя.
            if packet.r#type == crate::protocol::PacketType::DirectMessage as i32 {
                // ОБНОВЛЕНИЕ: раньше, если сессии с отправителем ещё не
                // было, decrypt_message падал с NoSession и просто
                // логировался тут как warn — первое сообщение от
                // незнакомца было НЕВОЗМОЖНО принять в принципе, потому
                // что SessionManager::accept_incoming_session существовал,
                // но его нечем было вызвать (эфемерный X3DH-ключ
                // отправителя было негде передать). Теперь envelope несёт
                // EncryptedEnvelope::session_init на первом сообщении, и
                // session_manager.decrypt_message/decrypt_from сами
                // поднимают сессию как ответчик перед расшифровкой — этот
                // вызов ничего специально для этого делать не должен.
                match session_manager.decrypt_message(packet).await {
                    Ok((from, plaintext)) => {
                        info!("DirectMessage decrypted successfully from {}, len={}", from, plaintext.len());
                        if incoming.send(crate::network::IncomingMessage { from, plaintext }).is_err() {
                            warn!("Не удалось передать входящее сообщение выше по стеку — приёмник закрыт (приложение завершается?)");
                        }
                    }
                    Err(e) => warn!(
                        "Failed to decrypt direct message (NoSession здесь означает: не первое \
                         сообщение и не было ни активной, ни X3DH-инициализирующей сессии — не \
                         обязательно атака, может быть повтор/устаревший пакет): {}",
                        e
                    ),
                }
            } else {
                info!("Packet is final for us or not onion — handle as direct message");
            }
        }
    }

    Ok(())
}
