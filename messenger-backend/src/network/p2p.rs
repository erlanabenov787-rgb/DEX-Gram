//! Поднимает libp2p swarm: транспорт (TCP+QUIC), шифрование канала
//! (noise), мультиплексирование (yamux), и объединяет Kademlia+Identify+
//! Ping+Relay в один NetworkBehaviour.
//!
//! ВАЖНО: это шифрование ТРАНСПОРТНОГО канала (соединение с соседним
//! узлом), оно НЕ заменяет end-to-end шифрование из crypto/ratchet.rs —
//! оно дополнительно защищает от локального сетевого наблюдателя между
//! тобой и ближайшим relay.

use libp2p::{
    identify, kad, noise, ping, relay,
    request_response::{self, Codec},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures::StreamExt;
use std::io;
use std::time::Duration;

use std::collections::HashMap;
use tokio::sync::oneshot;

use crate::config::Config;
use crate::identity::Identity;
use crate::network::{dispatcher, dht, IncomingReceiver, IncomingSender};
use crate::network::relay::registry::{RelayEntry, RelayRegistry};
use crate::protocol::{DhtRecord, Packet, PreKeyBundleRecord, RelayDescriptorRecord};
use crate::session::manager::{PeerIdentitySource, SessionManager};
use std::sync::Arc;

/// Messaging protocol name
#[derive(Debug, Clone)]
pub struct MessengerProtocol;

impl AsRef<str> for MessengerProtocol {
    fn as_ref(&self) -> &str {
        "/messenger/msg/1.0.0"
    }
}

/// Bincode-based codec for Packet (simple length-prefixed)
#[derive(Clone, Default)]
pub struct MessengerCodec;

#[async_trait]
impl Codec for MessengerCodec {
    type Protocol = MessengerProtocol;
    type Request = Packet;
    type Response = Packet;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut data = vec![0u8; len];
        io.read_exact(&mut data).await?;
        bincode::deserialize(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.read_request(&MessengerProtocol, io).await
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        io.flush().await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.write_request(&MessengerProtocol, io, res).await
    }
}

#[derive(NetworkBehaviour)]
pub struct MessengerBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub relay: relay::Behaviour,
    pub messaging: request_response::Behaviour<MessengerCodec>,
}

/// Один и тот же `pending_lookups` теперь обслуживает два разных типа
/// DHT-записей (UserRecord и PreKeyBundle) — этот enum позволяет
/// handle_kademlia_event понять, какой тип декодировать и в какой
/// oneshot отправить результат, не заводя две отдельные HashMap (что
/// потребовало бы дублировать логику вставки/удаления по QueryId).
enum PendingDhtQuery {
    UserRecord(oneshot::Sender<anyhow::Result<DhtRecord>>),
    PreKeyBundle(oneshot::Sender<anyhow::Result<PreKeyBundleRecord>>),
    RelayDescriptor(oneshot::Sender<anyhow::Result<RelayDescriptorRecord>>),
}

pub struct NodeHandle {
    pub swarm: Swarm<MessengerBehaviour>,
    pub local_peer_id: PeerId,
    pub(crate) session_manager: crate::session::manager::SessionManager,
    pub(crate) relay_scoring: crate::network::relay::RelayScoring,
    mailbox_service: crate::network::mailbox::MailboxService,
    #[allow(dead_code)] // Пока не используется напрямую вне relay_scoring/mailbox_service (Phase 5/6 будет читать историю отсюда).
    database: Arc<crate::storage::Database>,
    our_onion_secret: x25519_dalek::StaticSecret,
    /// Динамический реестр relay-узлов. Заполняется bootstrap-ом через
    /// NodeCommand::UpdateRelays. Используется для onion routing и как
    /// источник relay_id для mailbox fetch / dummy traffic.
    relay_registry: Arc<RelayRegistry>,
    pending_lookups: HashMap<kad::QueryId, PendingDhtQuery>,
    /// Кеш последней опубликованной DhtRecord — нужен для периодического
    /// переопубликования (NodeCommand::RepublishDht). None до первого
    /// вызова publish_my_record.
    my_dht_record: Option<crate::protocol::DhtRecord>,
    /// Кеш последнего опубликованного PreKeyBundle — аналогично.
    my_prekey_bundle: Option<crate::protocol::PreKeyBundleRecord>,
    /// Кеш mailbox_candidates из DHT-записей собеседников — заполняется
    /// в handle_kademlia_event при каждом успешном UserRecord lookup
    /// (инициируется DhtLookupSource::fetch_bundle при первом X3DH).
    /// Используется dispatcher::send_message для форсирования exit-хопа
    /// в onion-цепочке именно на relay, которые получатель реально
    /// опрашивает — без этого сообщение могло осесть на relay, который
    /// получатель никогда не запрашивает через fetch_mailbox.
    pub(crate) known_mailbox_candidates: HashMap<crate::identity::UserId, Vec<crate::network::RelayId>>,
    /// Приёмный конец канала, в который DhtLookupSource (см.
    /// network/dht/lookup.rs) кладёт запросы на DHT-поиск —
    /// PreKeyBundleSource::fetch_bundle и будущий OnionKeySource
    /// используют его вместо прямого доступа к Swarm (которого у них
    /// нет). РАНЬШЕ этот receiver создавался и СРАЗУ ДРОПАЛСЯ в start()
    /// (`let (dht_lookup_tx, _dht_lookup_rx) = ...`), из-за чего любой
    /// fetch_bundle() зависал до таймаута с "channel closed" — теперь
    /// он живёт здесь и вычитывается в run()/run_with_commands().
    dht_lookup_rx: tokio::sync::mpsc::UnboundedReceiver<dht::LookupRequest>,
    outbound_tx: crate::network::OutboundSender,
    outbound_rx: crate::network::OutboundReceiver,
    /// Куда кладём успешно расшифрованные входящие сообщения — читает
    /// это приложение (CLI main.rs или Tauri lib.rs), не сам NodeHandle.
    incoming_tx: IncomingSender,
}

/// Команда "сделай что-то с сетью", присылаемая снаружи (например из
/// Tauri command handler) в задачу, которая владеет `NodeHandle` внутри
/// `run_with_commands`. Нужно, т.к. `NodeHandle::run` забирает `self` по
/// значению — единственный способ повлиять на уже запущенный нод
/// снаружи это канал, а не прямой вызов метода.
pub enum NodeCommand {
    SendText {
        to: crate::identity::UserId,
        text: Vec<u8>,
        respond_to: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Спросить конкретный relay "отдай мои оффлайн-сообщения" (см.
    /// network::dispatcher::fetch_mailbox). Ответ приходит не через
    /// `respond_to` синхронно, а асинхронно позже через
    /// request_response::Message::Response -> handle_behaviour_event,
    /// который сам расшифрует и положит результат в incoming_tx — тем же
    /// путём, что обычные входящие сообщения. `respond_to` здесь только
    /// подтверждает, что ЗАПРОС был отправлен (или почему не вышло
    /// отправить), а не что сообщения получены.
    FetchMailbox {
        relay_id: String,
        respond_to: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Отправить DummyTraffic-пакет конкретному relay для защиты
    /// метаданных: наблюдатель не должен отличать реальные сообщения
    /// от шума по частоте/паттерну трафика. Fire-and-forget — нет
    /// respond_to, ошибки логируются только как trace.
    SendDummy {
        relay_id: String,
    },
    /// Переопубликовать собственную DhtRecord + PreKeyBundle в Kademlia
    /// (вызывается background-задачей каждые DHT_REPUBLISH_INTERVAL_SECS).
    /// Если my_dht_record или my_prekey_bundle ещё не закешированы —
    /// пропускаем с warn (значит первый publish ещё не был вызван).
    RepublishDht,
    /// Обновить список relay-узлов, полученный от bootstrap.
    ///
    /// Вызывается когда клиент получает список relay от bootstrap.
    /// NodeHandle: обновляет RelayRegistry, подключается к новым relay,
    /// сохраняет их репутацию в БД, отправляет начальный mailbox fetch.
    ///
    /// Пользователь relay не вводит вручную — список приходит автоматически.
    UpdateRelays {
        relays: Vec<RelayEntry>,
    },
    /// Найти пользователя по UserID через DHT (Kademlia).
    ///
    /// NodeHandle запускает запрос, кладёт respond_to в pending_lookups.
    /// Ответ приходит асинхронно — когда Kademlia вернёт запись,
    /// pending_lookups-обработчик стрельнёт respond_to с результатом.
    LookupUser {
        user_id: String,
        respond_to: oneshot::Sender<anyhow::Result<DhtRecord>>,
    },
}

impl NodeHandle {
    pub async fn start(
        cfg: &Config,
        identity: Arc<Identity>,
        identity_source: Arc<dyn PeerIdentitySource>,
        x3dh_identity: x25519_dalek::StaticSecret,
        our_signed_prekey: x25519_dalek::StaticSecret,
        our_one_time_prekeys: Vec<x25519_dalek::StaticSecret>,
        our_onion_secret: x25519_dalek::StaticSecret,
        // Динамический реестр relay-узлов. Создаётся снаружи (main.rs /
        // lib.rs) и передаётся сюда, чтобы фоновые задачи и NodeHandle
        // использовали один и тот же экземпляр — обновление через
        // NodeCommand::UpdateRelays видно всем сразу.
        relay_registry: Arc<RelayRegistry>,
    ) -> anyhow::Result<(Self, IncomingReceiver)> {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(keypair.public());
        tracing::info!("libp2p PeerId: {local_peer_id}");

        let mut swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_behaviour(|key| {
                let store = kad::store::MemoryStore::new(key.public().to_peer_id());
                let mut kad_config = kad::Config::default();
                kad_config.set_query_timeout(Duration::from_secs(30));

                MessengerBehaviour {    
                    kademlia: kad::Behaviour::with_config(    
                        key.public().to_peer_id(),    
                        store,    
                        kad_config,    
                    ),    
                    identify: identify::Behaviour::new(identify::Config::new(    
                        "/messenger/1.0.0".to_string(),    
                        key.public(),    
                    )),    
                    ping: ping::Behaviour::default(),    
                    relay: relay::Behaviour::new(key.public().to_peer_id(), Default::default()),    
                    messaging: request_response::Behaviour::new(    
                        std::iter::once((MessengerProtocol, request_response::ProtocolSupport::Full)),    
                        request_response::Config::default(),    
                    ),    
                }    
            })?    
            .build();    

        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", cfg.listen_port).parse()?;    
        swarm.listen_on(listen_addr)?;    

        for bootstrap in &cfg.bootstrap_nodes {    
            if let Ok(addr) = bootstrap.parse::<Multiaddr>() {    
                if let Err(e) = swarm.dial(addr.clone()) {    
                    tracing::warn!("Не удалось подключиться к bootstrap {addr}: {e}");    
                }    
            }    
        }    

        // Relay не подключаем при старте — они придут от bootstrap
        // через NodeCommand::UpdateRelays (см. handle_command).

        swarm.behaviour_mut().kademlia.bootstrap().ok();    


        let conn = rusqlite::Connection::open_in_memory()    
            .expect("Failed to open in-memory session db");    
        let session_store: std::sync::Arc<dyn crate::storage::session_store::SessionStore> =    
            std::sync::Arc::new(    
                crate::storage::session_store::SqliteSessionStore::open(conn)    
                    .expect("Failed to init SqliteSessionStore"),    
            );    

        let (dht_lookup_tx, dht_lookup_rx) = tokio::sync::mpsc::unbounded_channel();    
        let bundle_source: std::sync::Arc<dyn crate::session::manager::PreKeyBundleSource> =    
            std::sync::Arc::new(crate::network::dht::lookup::DhtLookupSource::new(dht_lookup_tx));    

        let session_manager = SessionManager::new(    
            session_store,    
            x3dh_identity,    
            our_signed_prekey,
            our_one_time_prekeys,
            bundle_source,    
            identity,    
            identity_source,    
        );    

        let database = std::sync::Arc::new(    
            crate::storage::Database::open(&cfg.db_path)    
                .map_err(|e| anyhow::anyhow!("не удалось открыть базу {}: {e}", cfg.db_path))?,    
        );    

        // Relay в базу не засеваем при старте — они придут от bootstrap
        // через NodeCommand::UpdateRelays и будут добавлены тогда же.

        let onion_key_source: Arc<dyn crate::network::relay::scoring::OnionKeySource> =
            relay_registry.clone();
        let relay_scoring = crate::network::relay::RelayScoring::new(database.clone(), onion_key_source);    

        let mailbox_conn = rusqlite::Connection::open(&cfg.db_path)    
            .map_err(|e| anyhow::anyhow!("не удалось открыть mailbox-соединение: {e}"))?;    
        let mailbox_store: std::sync::Arc<dyn crate::storage::mailbox_store::MailboxStore> =    
            std::sync::Arc::new(    
                crate::storage::mailbox_store::SqliteMailboxStore::open(mailbox_conn)    
                    .map_err(|e| anyhow::anyhow!("не удалось инициализировать mailbox store: {e}"))?,    
            );    
        let mailbox_service = crate::network::mailbox::MailboxService::new(mailbox_store);    

        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel();    
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::unbounded_channel();    

        let node = Self {    
            swarm,    
            local_peer_id,    
            session_manager,    
            relay_scoring,    
            mailbox_service,    
            database,    
            our_onion_secret,    
            relay_registry,
            pending_lookups: HashMap::new(),    
            my_dht_record: None,
            my_prekey_bundle: None,
            known_mailbox_candidates: HashMap::new(),
            dht_lookup_rx,    
            outbound_tx,    
            outbound_rx,    
            incoming_tx,    
        };
        Ok((node, incoming_rx))
    }

    pub fn publish_my_record(&mut self, record: &DhtRecord) -> anyhow::Result<()> {
        dht::publish_record(&mut self.swarm.behaviour_mut().kademlia, record)?;
        // Кешируем для периодического republish (NodeCommand::RepublishDht).
        self.my_dht_record = Some(record.clone());
        Ok(())
    }

    pub fn publish_my_prekey_bundle(&mut self, record: &PreKeyBundleRecord) -> anyhow::Result<()> {
        dht::publish_prekey_bundle(&mut self.swarm.behaviour_mut().kademlia, record)?;
        // Кешируем для периодического republish.
        self.my_prekey_bundle = Some(record.clone());
        Ok(())
    }

    pub async fn send_packet(&mut self, target_peer_id: &str, packet: crate::protocol::Packet) -> anyhow::Result<()> {
        use std::str::FromStr;
        let peer_id = PeerId::from_str(target_peer_id)
            .map_err(|_| anyhow::anyhow!("Invalid PeerId"))?;

        tracing::info!("Sending real Packet via RequestResponse to {}", peer_id);    

        let request_id = self.swarm.behaviour_mut().messaging.send_request(&peer_id, packet);    
        tracing::debug!("Request sent, id={:?}", request_id);    
        Ok(())
    }

    pub async fn send_to_user(&mut self, target: &str, packet: crate::protocol::Packet) -> anyhow::Result<()> {
        self.send_packet(target, packet).await
    }

    pub fn lookup_user(
        &mut self,
        user_id: &crate::identity::UserId,
    ) -> oneshot::Receiver<anyhow::Result<DhtRecord>> {
        let query_id = dht::lookup_user(&mut self.swarm.behaviour_mut().kademlia, user_id);
        let (tx, rx) = oneshot::channel();
        self.pending_lookups.insert(query_id, PendingDhtQuery::UserRecord(tx));
        rx
    }

    /// Обрабатывает запрос, пришедший из DhtLookupSource через
    /// dht_lookup_rx (см. поле выше) — запускает соответствующий
    /// Kademlia get_record и регистрирует ожидающий oneshot в
    /// pending_lookups, чтобы handle_kademlia_event знал, куда прислать
    /// результат когда запрос завершится.
    fn handle_lookup_request(&mut self, req: dht::LookupRequest) {
        match req {
            dht::LookupRequest::UserRecord { user_id, respond_to } => {
                let query_id = dht::lookup_user(&mut self.swarm.behaviour_mut().kademlia, &user_id);
                self.pending_lookups
                    .insert(query_id, PendingDhtQuery::UserRecord(respond_to));
            }
            dht::LookupRequest::PreKeyBundle { user_id, respond_to } => {
                let query_id =
                    dht::lookup_prekey_bundle(&mut self.swarm.behaviour_mut().kademlia, &user_id);
                self.pending_lookups
                    .insert(query_id, PendingDhtQuery::PreKeyBundle(respond_to));
            }
            dht::LookupRequest::RelayDescriptor { relay_id, respond_to } => {
                let query_id = dht::lookup_relay_descriptor(
                    &mut self.swarm.behaviour_mut().kademlia,
                    &relay_id,
                );
                self.pending_lookups
                    .insert(query_id, PendingDhtQuery::RelayDescriptor(respond_to));
            }
        }
    }

    /// Явный поиск relay-дескриптора — вызывается снаружи (например
    /// для диагностики или pre-warming кеша relay-ключей).
    pub fn lookup_relay_descriptor(
        &mut self,
        relay_id: &str,
    ) -> oneshot::Receiver<anyhow::Result<RelayDescriptorRecord>> {
        let query_id = dht::lookup_relay_descriptor(
            &mut self.swarm.behaviour_mut().kademlia,
            &relay_id.to_string(),
        );
        let (tx, rx) = oneshot::channel();
        self.pending_lookups
            .insert(query_id, PendingDhtQuery::RelayDescriptor(tx));
        rx
    }

    /// Публикует RelayDescriptorRecord в Kademlia DHT — вызывается
    /// при старте relay-узла (cfg.is_relay == true), чтобы другие
    /// узлы могли найти его onion_public_key через DHT и строить
    /// через него onion-маршруты без захардкоженного конфига.
    pub fn publish_my_relay_descriptor(
        &mut self,
        record: &RelayDescriptorRecord,
    ) -> anyhow::Result<()> {
        dht::publish_relay_descriptor(&mut self.swarm.behaviour_mut().kademlia, record)?;
        Ok(())
    }

    pub async fn run(mut self) {
        // `dht_lookup_open` — защита от busy-loop: если dht_lookup_rx
        // вдруг закроется (в норме не должно, т.к. Sender живёт внутри
        // self.session_manager.bundle_source, то есть ровно столько же,
        // сколько сам self), recv() на закрытом канале возвращает
        // готовый None немедленно на каждой итерации select! — без этого
        // флага это была бы бесконечная горячая петля вместо аккуратного
        // "больше не опрашивать этот arm".
        let mut dht_lookup_open = true;
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            tracing::info!("Слушаем на {address}");
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            tracing::info!("Соединение установлено с {peer_id}");
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            tracing::warn!("Соединение с {peer_id} закрыто: {cause:?}");
                        }
                        SwarmEvent::Behaviour(event) => {
                            self.handle_behaviour_event(event).await;
                        }
                        _ => {}
                    }
                }
                maybe_req = self.dht_lookup_rx.recv(), if dht_lookup_open => {
                    match maybe_req {
                        Some(req) => self.handle_lookup_request(req),
                        None => {
                            dht_lookup_open = false;
                            tracing::warn!(
                                "dht_lookup_rx закрылся неожиданно — PreKeyBundleSource::fetch_bundle \
                                 больше не получит ответов от DHT до перезапуска нода"
                            );
                        }
                    }
                }
            }
        }
    }

    /// То же самое, что `run`, но параллельно слушает канал команд снаружи
    /// (например от Tauri command handler-а) — используется в
    /// src-tauri/src/lib.rs, т.к. UI не может держать `&mut NodeHandle`
    /// напрямую (нод уже "живёт" внутри этого бесконечного цикла).
    pub async fn run_with_commands(mut self, mut commands: tokio::sync::mpsc::UnboundedReceiver<NodeCommand>) {
        // См. комментарий у dht_lookup_open в run() выше — та же защита
        // от busy-loop, тут просто вторая копия того же паттерна, т.к.
        // run() и run_with_commands() — два разных тела цикла, а не один
        // общий (run_with_commands забирает ещё и commands).
        let mut dht_lookup_open = true;
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            tracing::info!("Слушаем на {address}");
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            tracing::info!("Соединение установлено с {peer_id}");
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            tracing::warn!("Соединение с {peer_id} закрыто: {cause:?}");
                        }
                        SwarmEvent::Behaviour(event) => {
                            self.handle_behaviour_event(event).await;
                        }
                        _ => {}
                    }
                }
                maybe_cmd = commands.recv() => {
                    match maybe_cmd {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => {
                            tracing::info!("Канал команд закрыт (приложение завершается?), останавливаю node loop");
                            break;
                        }
                    }
                }
                maybe_req = self.dht_lookup_rx.recv(), if dht_lookup_open => {
                    match maybe_req {
                        Some(req) => self.handle_lookup_request(req),
                        None => {
                            dht_lookup_open = false;
                            tracing::warn!(
                                "dht_lookup_rx закрылся неожиданно — PreKeyBundleSource::fetch_bundle \
                                 больше не получит ответов от DHT до перезапуска нода"
                            );
                        }
                    }
                }
            }
        }
    }

    async fn handle_command(&mut self, cmd: NodeCommand) {
        match cmd {
            NodeCommand::SendText { to, text, respond_to } => {
                let result = dispatcher::send_message(self, &to, &text).await;
                if let Err(e) = &result {
                    tracing::warn!("Не удалось отправить сообщение для {to}: {e:?}");
                }
                let _ = respond_to.send(result);
            }
            NodeCommand::FetchMailbox { relay_id, respond_to } => {
                let result = dispatcher::fetch_mailbox(self, &relay_id).await;
                if let Err(e) = &result {
                    tracing::warn!("Не удалось отправить MAILBOX_FETCH на {relay_id}: {e:?}");
                }
                let _ = respond_to.send(result);
            }
            NodeCommand::SendDummy { relay_id } => {
                if let Err(e) = dispatcher::send_dummy_packet(self, &relay_id).await {
                    tracing::trace!("Не удалось отправить dummy трафик на {relay_id}: {e:?}");
                }
            }
            NodeCommand::UpdateRelays { relays } => {
                let count = relays.len();
                // 1. Обновляем реестр — новый список виден всем задачам сразу.
                self.relay_registry.update(relays.clone());

                // 2. Подключаемся к новым relay и сохраняем репутацию в БД.
                for entry in &relays {
                    if let Ok(addr) = entry.address.parse::<Multiaddr>() {
                        if let Err(e) = self.swarm.dial(addr.clone()) {
                            tracing::warn!(
                                "UpdateRelays: не удалось подключиться к relay {} ({addr}): {e}",
                                entry.relay_id
                            );
                        }
                    } else {
                        tracing::warn!(
                            "UpdateRelays: невалидный multiaddr у relay {}: {}",
                            entry.relay_id,
                            entry.address
                        );
                    }
                    if let Err(e) = self.database.upsert_relay_reputation(
                        &entry.relay_id,
                        &entry.address,
                        0.0,
                    ) {
                        tracing::warn!(
                            "UpdateRelays: не удалось записать relay {} в БД: {e}",
                            entry.relay_id
                        );
                    }
                }

                // 3. Немедленный mailbox fetch у каждого нового relay —
                // сообщения, накопившиеся пока мы не знали этот relay.
                for entry in &relays {
                    if let Err(e) = dispatcher::fetch_mailbox(self, &entry.relay_id).await {
                        tracing::debug!(
                            "UpdateRelays: начальный fetch_mailbox для relay {} не удался: {e:?}",
                            entry.relay_id
                        );
                    }
                }

                tracing::info!(
                    "UpdateRelays: реестр обновлён ({count} relay), начальный mailbox fetch отправлен"
                );
            }
            NodeCommand::LookupUser { user_id, respond_to } => {
                let query_id = dht::lookup_user(&mut self.swarm.behaviour_mut().kademlia, &user_id);
                self.pending_lookups.insert(query_id, PendingDhtQuery::UserRecord(respond_to));
            }
            NodeCommand::RepublishDht => {
                // Клонируем перед вызовом — publish_my_record/bundle берут &mut self,
                // что несовместимо с одновременным borrow my_dht_record как &.
                let maybe_record = self.my_dht_record.clone();
                let maybe_bundle = self.my_prekey_bundle.clone();

                if let Some(record) = maybe_record {
                    match self.publish_my_record(&record) {
                        Ok(()) => tracing::info!("DhtRecord переопубликован"),
                        Err(e) => tracing::warn!("Не удалось переопубликовать DhtRecord: {e}"),
                    }
                } else {
                    tracing::warn!("RepublishDht: my_dht_record пуст — первый publish ещё не был вызван?");
                }

                if let Some(bundle) = maybe_bundle {
                    match self.publish_my_prekey_bundle(&bundle) {
                        Ok(()) => tracing::info!("PreKeyBundle переопубликован"),
                        Err(e) => tracing::warn!("Не удалось переопубликовать PreKeyBundle: {e}"),
                    }
                } else {
                    tracing::warn!("RepublishDht: my_prekey_bundle пуст — первый publish ещё не был вызван?");
                }
            }
        }
    }

    async fn handle_behaviour_event(&mut self, event: MessengerBehaviourEvent) {
        match event {
            MessengerBehaviourEvent::Kademlia(kad_event) => {
                self.handle_kademlia_event(kad_event);
            }
            MessengerBehaviourEvent::Identify(id_event) => {
                tracing::debug!("Identify event: {id_event:?}");
            }
            MessengerBehaviourEvent::Ping(ping_event) => {
                tracing::trace!("Ping: {ping_event:?}");
            }
            MessengerBehaviourEvent::Relay(relay_event) => {
                tracing::debug!("Relay event: {relay_event:?}");
            }
            MessengerBehaviourEvent::Messaging(msg_event) => {
                use request_response::Event;
                match msg_event {
                    Event::Message { peer, message } => {
                        match message {
                            request_response::Message::Request { request, channel, .. } => {
                                tracing::info!("Received real Packet via RequestResponse from {peer}");

                                let response_opt = match dispatcher::handle_incoming_packet(
                                    request,
                                    &self.session_manager,
                                    &self.our_onion_secret,
                                    &self.mailbox_service,
                                    &self.outbound_tx,
                                    &self.incoming_tx,
                                )
                                .await
                                {
                                    Ok(opt) => opt,
                                    Err(e) => {
                                        tracing::warn!("Failed to handle incoming packet from {peer}: {e:?}");
                                        None
                                    }
                                };

                                // Пересылаем relay-пакеты, поставленные диспетчером в очередь
                                let mut to_send = Vec::new();
                                while let Ok(cmd) = self.outbound_rx.try_recv() {
                                    to_send.push(cmd);
                                }
                                for cmd in to_send {
                                    if let Err(e) = self.send_packet(&cmd.target_peer_id, cmd.packet).await {
                                        tracing::warn!(
                                            "Не удалось переслать пакет дальше на {}: {e:?}",
                                            cmd.target_peer_id
                                        );
                                    }
                                }

                                // Отправляем содержательный ответ (MAILBOX_FETCH) или
                                // стандартный пустой ack для всех остальных типов пакетов.
                                let ack = response_opt.unwrap_or_else(|| crate::protocol::Packet {
                                    protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
                                    r#type: crate::protocol::PacketType::Unknown.into(),
                                    encrypted_payload: Vec::new(),
                                    sender_signature: Vec::new(),
                                    padding_len: 0,
                                    recipient_user_id: String::new(),
                                });
                                let _ = self.swarm.behaviour_mut().messaging.send_response(channel, ack);
                            }
                            request_response::Message::Response { response, .. } => {
                                // Единственный тип ответа, несущий полезную нагрузку —
                                // MAILBOX_FETCH: payload = bincode(Vec<Vec<u8>>), каждый
                                // inner blob = bincode(EncryptedEnvelope) из ratchet.
                                use crate::protocol::PacketType;
                                if PacketType::try_from(response.r#type).unwrap_or(PacketType::Unknown)
                                    == PacketType::MailboxFetch
                                {
                                    match bincode::deserialize::<Vec<Vec<u8>>>(&response.encrypted_payload) {
                                        Ok(envelopes) => {
                                            tracing::info!(
                                                "Получен MAILBOX_FETCH ответ от {peer}: {} сообщений",
                                                envelopes.len()
                                            );
                                            for blob in envelopes {
                                                // Каждый blob — это то же, что и в onion exit:
                                                // bincode(EncryptedEnvelope). Заворачиваем в Packet
                                                // как DirectMessage, чтобы session_manager смог
                                                // расшифровать его обычным путём.
                                                let fake_packet = crate::protocol::Packet {
                                                    protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
                                                    r#type: crate::protocol::PacketType::DirectMessage.into(),
                                                    encrypted_payload: blob,
                                                    sender_signature: Vec::new(),
                                                    padding_len: 0,
                                                    recipient_user_id: String::new(),
                                                };
                                                match self.session_manager.decrypt_message(fake_packet).await {
                                                    Ok((from, plaintext)) => {
                                                        tracing::info!(
                                                            "Mailbox сообщение расшифровано от {from}, len={}",
                                                            plaintext.len()
                                                        );
                                                        if self.incoming_tx.send(crate::network::IncomingMessage {
                                                            from,
                                                            plaintext,
                                                        }).is_err() {
                                                            tracing::warn!(
                                                                "incoming_tx закрыт — не удалось передать mailbox-сообщение выше"
                                                            );
                                                        }
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(
                                                            "Не удалось расшифровать mailbox-сообщение: {e}"
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "MAILBOX_FETCH ответ от {peer}: ошибка десериализации payload: {e}"
                                            );
                                        }
                                    }
                                } else {
                                    tracing::info!("Received transport-level response from {peer} (non-mailbox)");
                                }
                            }
                        }
                    }    
                    Event::OutboundFailure { peer, error, .. } => {    
                        tracing::warn!("Outbound messaging failure to {peer}: {error:?}");    
                    }
                    Event::InboundFailure { peer, error, .. } => {
                        tracing::warn!("Inbound messaging failure from {peer}: {error:?}");
                    }    
                    _ => {}
                }    
            }
        }
    }

    #[allow(dead_code)] // Заглушка под будущий разбор relay-событий напрямую из libp2p::relay::Event.
    fn try_parse_packet_from_relay(&self, _event: &libp2p::relay::Event) -> Option<crate::protocol::Packet> {
        None                                              
    }

    fn handle_kademlia_event(&mut self, event: kad::Event) {
        use kad::{Event as KadEvent, QueryResult};
        let KadEvent::OutboundQueryProgressed { id, result, .. } = event else {
            return;
        };
        match result {
            QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))) => {
                if let Some(pending) = self.pending_lookups.remove(&id) {
                    // Тут только декодируем protobuf — подпись/PoW не
                    // проверяем на этом уровне (тот же пробел, что был
                    // здесь и раньше для DhtRecord). Для PreKeyBundle это
                    // не проблема: реальная проверка подписи происходит
                    // в DhtLookupSource::fetch_bundle, у которого уже
                    // есть ed25519-ключ владельца из отдельного lookup'а
                    // DhtRecord — тут, в p2p.rs, этого ключа просто нет.
                    match pending {
                        PendingDhtQuery::UserRecord(sender) => {
                            let parsed: anyhow::Result<DhtRecord> = prost::Message::decode(peer_record.record.value.as_slice())
                                .map_err(|e| anyhow::anyhow!("Failed to decode DHT record: {e}"));
                            // Кешируем mailbox_candidates, пока запись у нас "в руках" —
                            // dispatcher::send_message использует этот кеш для форсирования
                            // exit-хопа на relay получателя (см. known_mailbox_candidates).
                            if let Ok(ref record) = parsed {
                                if !record.mailbox_candidates.is_empty() {
                                    tracing::debug!(
                                        "Кешируем {} mailbox_candidates для {}",
                                        record.mailbox_candidates.len(),
                                        record.user_id,
                                    );
                                    self.known_mailbox_candidates.insert(
                                        record.user_id.clone(),
                                        record.mailbox_candidates.clone(),
                                    );
                                }
                            }
                            let _ = sender.send(parsed);
                        }
                        PendingDhtQuery::PreKeyBundle(sender) => {
                            let parsed: anyhow::Result<PreKeyBundleRecord> =
                                prost::Message::decode(peer_record.record.value.as_slice()).map_err(|e| {
                                    anyhow::anyhow!("Failed to decode prekey bundle record: {e}")
                                });
                            let _ = sender.send(parsed);
                        }
                        PendingDhtQuery::RelayDescriptor(sender) => {
                            let parsed: anyhow::Result<RelayDescriptorRecord> =
                                prost::Message::decode(peer_record.record.value.as_slice()).map_err(|e| {
                                    anyhow::anyhow!("Failed to decode relay descriptor record: {e}")
                                });
                            let _ = sender.send(parsed);
                        }
                    }
                }
            }
            QueryResult::GetRecord(Err(e)) => {
                if let Some(pending) = self.pending_lookups.remove(&id) {
                    let err = anyhow::anyhow!("Kademlia record query failed: {e:?}");
                    match pending {
                        PendingDhtQuery::UserRecord(sender) => {
                            let _ = sender.send(Err(err));
                        }
                        PendingDhtQuery::PreKeyBundle(sender) => {
                            let _ = sender.send(Err(err));
                        }
                        PendingDhtQuery::RelayDescriptor(sender) => {
                            let _ = sender.send(Err(err));
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

