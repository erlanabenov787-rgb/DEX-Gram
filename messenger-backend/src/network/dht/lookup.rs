//! Поиск UserID / PreKeyBundle / RelayDescriptor в DHT и разбор ответа.
//!
//! DhtLookupSource реализует:
//! - `session::PreKeyBundleSource::fetch_bundle` — РЕАЛЬНО работает:
//!   тянет DhtRecord владельца (чтобы достать его ed25519 verifying key),
//!   затем PreKeyBundleRecord из отдельного DHT-ключа, проверяет подпись
//!   и конвертирует в crypto::x3dh::PreKeyBundle.
//!
//! - `relay::scoring::OnionKeySource::fetch_onion_key` — РЕАЛЬНО работает:
//!   тянет RelayDescriptorRecord из DHT-ключа Hash("relay:" + relay_id),
//!   извлекает X25519 onion_public_key. Подпись relay'я пока не проверяется
//!   (для этого нужен реестр ed25519 identity keys relay-узлов — отдельная
//!   задача); PoW в записи защищает от флуда фиктивными дескрипторами.

use libp2p::kad;

use crate::identity::UserId;
use crate::network::onion::RelayOnionKey;
use crate::network::RelayId;
use crate::protocol::{DhtRecord, PreKeyBundleRecord, RelayDescriptorRecord};

use super::record::{DhtRecordBuilder, PreKeyBundleRecordBuilder};

/// Запускает поиск UserID в DHT. Результат приходит асинхронно как
/// SwarmEvent::Behaviour(MessengerBehaviourEvent::Kademlia(..)) —
/// см. p2p.rs handle_behaviour_event, где нужно сопоставить query_id
/// с ожидающим запросом (например через HashMap<QueryId, oneshot::Sender>).
pub fn lookup_user(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    user_id: &UserId,
) -> kad::QueryId {
    let key = super::record::record_key_for_user(user_id);
    kademlia.get_record(key)
}

/// Парсит сырые байты, пришедшие из Kademlia GetRecord, обратно в
/// DhtRecord и сразу проверяет её валидность.
pub fn parse_and_verify_record(
    raw_value: &[u8],
    verify_fn: impl FnOnce(&[u8], &[u8]) -> bool,
) -> anyhow::Result<DhtRecord> {
    let record: DhtRecord = prost::Message::decode(raw_value)?;
    DhtRecordBuilder::verify(&record, verify_fn)?;
    Ok(record)
}

/// Запускает поиск PreKeyBundleRecord пользователя в DHT — отдельный
/// ключ от lookup_user (см. record::prekey_bundle_key_for_user).
pub fn lookup_prekey_bundle(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    user_id: &UserId,
) -> kad::QueryId {
    let key = super::record::prekey_bundle_key_for_user(user_id);
    kademlia.get_record(key)
}

/// Запускает поиск RelayDescriptorRecord в DHT — под ключом
/// Hash("relay:" + relay_id), отдельный домен от пользовательских записей.
pub fn lookup_relay_descriptor(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    relay_id: &RelayId,
) -> kad::QueryId {
    let key = super::record::relay_descriptor_key_for_relay(relay_id);
    kademlia.get_record(key)
}

/// Парсит сырые байты из Kademlia GetRecord в PreKeyBundleRecord и
/// проверяет подпись. В отличие от parse_and_verify_record выше,
/// verify_fn здесь обязательно приходит извне: PreKeyBundleRecord не
/// несёт ed25519 verifying key внутри себя (только x25519 DH-ключ), так
/// что self-contained проверка невозможна — ключ нужно достать отдельно
/// (см. DhtLookupSource::fetch_bundle ниже, который делает это через
/// DhtRecord того же пользователя).
pub fn parse_prekey_bundle_record(
    raw_value: &[u8],
    verify_fn: impl FnOnce(&[u8], &[u8]) -> bool,
) -> anyhow::Result<PreKeyBundleRecord> {
    let record: PreKeyBundleRecord = prost::Message::decode(raw_value)?;
    PreKeyBundleRecordBuilder::verify(&record, verify_fn)?;
    Ok(record)
}

/// Мост между сырым libp2p Kademlia event loop и async-интерфейсом,
/// который ждут session::SessionManager и relay::scoring::RelayScoring.
pub struct DhtLookupSource {
    pending: tokio::sync::mpsc::UnboundedSender<LookupRequest>,
}

pub enum LookupRequest {
    UserRecord {
        user_id: UserId,
        respond_to: tokio::sync::oneshot::Sender<anyhow::Result<DhtRecord>>,
    },
    PreKeyBundle {
        user_id: UserId,
        respond_to: tokio::sync::oneshot::Sender<anyhow::Result<PreKeyBundleRecord>>,
    },
    RelayDescriptor {
        relay_id: RelayId,
        respond_to: tokio::sync::oneshot::Sender<anyhow::Result<RelayDescriptorRecord>>,
    },
}

impl DhtLookupSource {
    pub fn new(pending: tokio::sync::mpsc::UnboundedSender<LookupRequest>) -> Self {
        Self { pending }
    }

    async fn fetch_user_record(&self, user_id: &UserId) -> crate::errors::Result<DhtRecord> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending
            .send(LookupRequest::UserRecord {
                user_id: user_id.clone(),
                respond_to: tx,
            })
            .map_err(|_| {
                crate::errors::MessengerError::Network(
                    "dht lookup channel closed — p2p event loop не запущен?".to_string(),
                )
            })?;

        let record = rx
            .await
            .map_err(|_| crate::errors::MessengerError::Timeout)?
            .map_err(|e| crate::errors::MessengerError::DhtRecordNotFound(e.to_string()))?;

        Ok(record)
    }

    /// Тянет НЕ проверенный (ещё) PreKeyBundleRecord — p2p.rs на своей
    /// стороне только декодирует protobuf, у него нет доступа к
    /// ed25519-ключу владельца, чтобы проверить подпись на месте.
    /// Проверка подписи — забота вызывающего (fetch_bundle ниже), у
    /// которого этот ключ уже есть после fetch_user_record.
    async fn fetch_prekey_bundle_record_unverified(
        &self,
        user_id: &UserId,
    ) -> crate::errors::Result<PreKeyBundleRecord> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending
            .send(LookupRequest::PreKeyBundle {
                user_id: user_id.clone(),
                respond_to: tx,
            })
            .map_err(|_| {
                crate::errors::MessengerError::Network(
                    "dht lookup channel closed — p2p event loop не запущен?".to_string(),
                )
            })?;

        let record = rx
            .await
            .map_err(|_| crate::errors::MessengerError::Timeout)?
            .map_err(|_| crate::errors::MessengerError::PreKeyBundleNotFound(user_id.clone()))?;

        Ok(record)
    }

    /// Тянет RelayDescriptorRecord из DHT. Подпись relay'я пока не
    /// проверяется на этом уровне (нет реестра relay identity keys), но
    /// PoW в записи защищает от флуда фиктивными дескрипторами.
    async fn fetch_relay_descriptor_unverified(
        &self,
        relay_id: &RelayId,
    ) -> crate::errors::Result<RelayDescriptorRecord> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending
            .send(LookupRequest::RelayDescriptor {
                relay_id: relay_id.clone(),
                respond_to: tx,
            })
            .map_err(|_| {
                crate::errors::MessengerError::Network(
                    "dht lookup channel closed — p2p event loop не запущен?".to_string(),
                )
            })?;

        let record = rx
            .await
            .map_err(|_| crate::errors::MessengerError::Timeout)?
            .map_err(|_| crate::errors::MessengerError::OnionKeyNotFound(relay_id.clone()))?;

        Ok(record)
    }
}

#[async_trait::async_trait]
impl crate::session::PreKeyBundleSource for DhtLookupSource {
    async fn fetch_bundle(
        &self,
        peer: &UserId,
    ) -> crate::errors::Result<crate::crypto::x3dh::PreKeyBundle> {
        // Шаг 1: DhtRecord peer'а несёт его ed25519 verifying key
        // (DhtRecord::public_key) — этим же ключом подписан
        // PreKeyBundleRecord::signed_prekey_signature. Без этого шага
        // нечем проверить подлинность бандла.
        let user_record = self.fetch_user_record(peer).await?;
        let verifying_key =
            crate::identity::Identity::verifying_key_from_bytes(&user_record.public_key)
                .ok_or_else(|| crate::errors::MessengerError::IdentityKeyNotFound(peer.clone()))?;

        // Шаг 2: тянем бандл (пока не проверенный) и проверяем его
        // подпись найденным выше ключом.
        // signed_prekey_signature покрывает только байты signed_prekey
        // (Signal-семантика) — см. record.rs::PreKeyBundleRecordBuilder.
        let raw_record = self
            .fetch_prekey_bundle_record_unverified(peer)
            .await?;

        PreKeyBundleRecordBuilder::verify(&raw_record, |msg, sig| {
            crate::identity::Identity::verify_bytes(&verifying_key, msg, sig)
        })
        .map_err(|_| crate::errors::MessengerError::InvalidPreKeySignature(peer.clone()))?;

        // Шаг 3: конвертируем protobuf-типы (bytes) в x25519-dalek типы,
        // которые ждёт crypto::x3dh::X3dhSession.
        let identity_key = parse_x25519_public(&raw_record.x3dh_identity_key)
            .ok_or_else(|| crate::errors::MessengerError::PreKeyBundleNotFound(peer.clone()))?;
        let signed_prekey = parse_x25519_public(&raw_record.signed_prekey)
            .ok_or_else(|| crate::errors::MessengerError::PreKeyBundleNotFound(peer.clone()))?;

        // Берём первый one-time prekey из пула. ЧЕСТНО: нет server-side
        // резервации/удаления использованных OTPK — если два инициатора
        // запросят бандл одновременно (race), оба получат один и тот же OTPK.
        // Для MVP приемлемо: DH1..DH3 всё равно защищают саму сессию.
        let one_time_prekey = raw_record
            .one_time_prekeys
            .first()
            .and_then(|bytes| parse_x25519_public(bytes));

        Ok(crate::crypto::x3dh::PreKeyBundle {
            identity_key,
            signed_prekey,
            signed_prekey_signature: raw_record.signed_prekey_signature,
            one_time_prekey,
        })
    }
}

fn parse_x25519_public(bytes: &[u8]) -> Option<x25519_dalek::PublicKey> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(x25519_dalek::PublicKey::from(arr))
}

#[async_trait::async_trait]
impl crate::network::relay::scoring::OnionKeySource for DhtLookupSource {
    async fn fetch_onion_key(&self, relay: &RelayId) -> crate::errors::Result<RelayOnionKey> {
        // Тянем дескриптор relay'я из DHT. Запись туда публикуется
        // relay-нодой при старте через NodeHandle::publish_my_relay_descriptor.
        // Подпись relay'я пока не проверяем на этом уровне (нет реестра
        // relay identity keys — отдельная задача Phase N+1); PoW в записи
        // достаточен для защиты от флуда фиктивными дескрипторами.
        let record = self.fetch_relay_descriptor_unverified(relay).await?;

        let onion_key = parse_x25519_public(&record.onion_public_key)
            .ok_or_else(|| crate::errors::MessengerError::OnionKeyNotFound(relay.clone()))?;

        Ok(onion_key)
    }
}
