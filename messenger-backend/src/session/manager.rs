//! Единая точка входа для остальной кодовой базы: "зашифруй это для
//! Боба", "расшифруй то, что пришло от Алисы". Сам решает, есть ли уже
//! ratchet-сессия с собеседником, и если нет — поднимает её через X3DH
//! (инициатором или ответчиком). network/ и services/ не должны знать
//! про DoubleRatchet или X3dhSession напрямую — только через этот manager.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::x3dh::{PreKeyBundle, X3dhSession};
use crate::crypto::{EncryptedEnvelope, SessionInit};
use crate::errors::{MessengerError, Result};
use crate::identity::{Identity, UserId};
use crate::session::state::{Session, SessionOrigin};
use crate::storage::session_store::SessionStore;
use crate::types::SessionId;

/// Абстракция над "где взять prekey bundle собеседника" — в реальности
/// это DHT lookup (network/dht/lookup.rs), но manager не должен знать
/// про libp2p, поэтому это trait, который network/ реализует.
#[async_trait::async_trait]
pub trait PreKeyBundleSource: Send + Sync {
    async fn fetch_bundle(&self, peer: &UserId) -> Result<PreKeyBundle>;
}

/// Абстракция над "где взять ed25519 verifying key собеседника, чтобы
/// проверить подпись на входящем сообщении". Отдельно от
/// `PreKeyBundleSource`, потому что identity-ключ (для подписи) и
/// x3dh-ключ (для DH) — разные ключи и могут приходить из разных мест
/// (DHT-запись против локальной таблицы контактов, куда пользователь
/// вручную вбил publicKeyHex — см. src-tauri add_contact).
#[async_trait::async_trait]
pub trait PeerIdentitySource: Send + Sync {
    async fn fetch_identity_key(&self, peer: &UserId) -> Result<ed25519_dalek::VerifyingKey>;
}

pub struct SessionManager {
    /// В памяти — для быстрого доступа на горячем пути отправки/приёма.
    /// Персистентность обеспечивает SessionStore (сериализованный
    /// root_secret + метаданные), т.к. процесс должен переживать рестарт
    /// не теряя возможность читать/писать существующим собеседникам.
    sessions: RwLock<HashMap<SessionId, Session>>,
    store: Arc<dyn SessionStore>,
    /// Наш статический X25519-ключ для X3DH (отдельный от ed25519
    /// identity-ключа в identity.rs — identity подписывает, этот ключ
    /// используется для Diffie-Hellman).
    x3dh_identity: StaticSecret,
    /// Наш опубликованный signed prekey (та же пара, что лежит в
    /// PreKeyBundleRecord.signed_prekey) — нужен здесь, а не только у
    /// вызывающего кода (main.rs/lib.rs, откуда публикуется бандл),
    /// потому что `accept_incoming_session` должен приватным ключом
    /// пересчитать те же DH-шаги, которые инициатор уже посчитал с
    /// нашим публичным.
    our_signed_prekey: StaticSecret,
    /// Пул наших one-time prekeys, ключ — публичный ключ (32 байта), как
    /// он выглядит в PreKeyBundleRecord.one_time_prekeys и в
    /// `EncryptedEnvelope::session_init.one_time_prekey_public`. Каждый
    /// ключ вычёркивается после первого использования (forward secrecy).
    /// ЧЕСТНО: та же race-condition оговорка, что у DhtLookupSource — два
    /// "первых сообщения" от разных инициаторов, почти одновременно
    /// выбравших один и тот же OTPK из уже устаревшего DHT-снэпшота,
    /// всё ещё могут столкнуться (второй просто не найдёт ключ здесь и
    /// откатится на DH-секрет без DH4, а не на ошибку — см. ниже).
    one_time_prekeys: RwLock<HashMap<[u8; 32], StaticSecret>>,
    bundle_source: Arc<dyn PreKeyBundleSource>,
    /// Наша ed25519 identity — нужна чтобы подписывать каждое исходящее
    /// сообщение (см. EncryptedEnvelope::sender_signature).
    my_identity: Arc<Identity>,
    /// Откуда брать verifying key собеседника для проверки входящих подписей.
    identity_source: Arc<dyn PeerIdentitySource>,
}

impl SessionManager {
    pub fn new(
        store: Arc<dyn SessionStore>,
        x3dh_identity: StaticSecret,
        our_signed_prekey: StaticSecret,
        one_time_prekeys: Vec<StaticSecret>,
        bundle_source: Arc<dyn PreKeyBundleSource>,
        my_identity: Arc<Identity>,
        identity_source: Arc<dyn PeerIdentitySource>,
    ) -> Self {
        let one_time_prekeys = one_time_prekeys
            .into_iter()
            .map(|sk| (PublicKey::from(&sk).to_bytes(), sk))
            .collect();
        Self {
            sessions: RwLock::new(HashMap::new()),
            store,
            x3dh_identity,
            our_signed_prekey,
            one_time_prekeys: RwLock::new(one_time_prekeys),
            bundle_source,
            my_identity,
            identity_source,
        }
    }

    /// Зашифровать сообщение для собеседника (поднимает сессию через X3DH
    /// если нужно), обернуть готовый envelope в транспортный Packet.
    pub async fn encrypt_message(&self, peer: &UserId, plaintext: &[u8]) -> Result<crate::protocol::Packet> {
        let envelope = self.encrypt_for(peer, plaintext).await?;
        let payload = bincode::serialize(&envelope)
            .map_err(|e| MessengerError::Serialization(e.to_string()))?;
        Ok(crate::protocol::Packet {
            protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
            r#type: crate::protocol::PacketType::DirectMessage.into(),
            encrypted_payload: payload,
            // Подпись уже стоит внутри envelope (sender_signature) — она
            // покрывает именно то, что нужно проверить получателю. Само
            // поле Packet::sender_signature осталось бы нужно только если
            // бы relay-узлы должны были проверять пакеты на своём уровне
            // (сейчас не должны — они не видят содержимое), так что не
            // дублируем подпись сюда.
            sender_signature: Vec::new(),
            padding_len: 0,
            recipient_user_id: String::new(),
        })
    }

    /// Наш собственный UserID — нужен вызывающему коду вне
    /// encrypt_for/decrypt_from (например dispatcher::fetch_mailbox,
    /// которому нужно знать "чей mailbox я вообще спрашиваю", раз это не
    /// шифрование конкретному собеседнику).
    pub fn my_user_id(&self) -> &UserId {
        &self.my_identity.user_id
    }

    /// Подписывает произвольные байты нашим ed25519 identity-ключом.
    /// Используется вне обычного encrypt_for/decrypt_from пути — сейчас
    /// только для MAILBOX_FETCH-запросов (network/dispatcher.rs::fetch_mailbox),
    /// которым нужна аутентификация "я владею этим UserID", но которые
    /// не являются обычным зашифрованным сообщением собеседнику.
    pub fn sign_own_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        self.my_identity.sign(bytes).to_bytes().to_vec()
    }

    /// Проверяет, что `signature` над `bytes` реально принадлежит
    /// `peer` — ищет verifying key через тот же identity_source, что
    /// использует decrypt_from для проверки подписи входящих сообщений.
    /// Используется relay-стороной MAILBOX_FETCH: не выдавать чужой
    /// mailbox тому, кто просто ЗАЯВИЛ чужой UserID в поле
    /// recipient_user_id, не подтвердив владение подписью.
    pub async fn verify_own_bytes(&self, peer: &UserId, bytes: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = self
            .identity_source
            .fetch_identity_key(peer)
            .await
            .map_err(|_| MessengerError::IdentityKeyNotFound(peer.clone()))?;
        Ok(Identity::verify_bytes(&verifying_key, bytes, signature))
    }

    /// Расшифровать входящий транспортный Packet: достаёт EncryptedEnvelope,
    /// определяет отправителя по `envelope.sender_id`, проверяет подпись и
    /// расшифровывает через сессию с этим peer. Возвращает (peer, plaintext)
    /// — раньше это было физически невозможно, т.к. peer было неоткуда
    /// взять (см. старый комментарий-заглушку, который был тут).
    pub async fn decrypt_message(&self, packet: crate::protocol::Packet) -> Result<(UserId, Vec<u8>)> {
        let envelope: EncryptedEnvelope = bincode::deserialize(&packet.encrypted_payload)
            .map_err(|e| MessengerError::Serialization(e.to_string()))?;
        let peer = envelope.sender_id.clone();
        let plaintext = self.decrypt_from(&peer, &envelope).await?;
        Ok((peer, plaintext))
    }

    /// Шифрует сообщение для peer, поднимая сессию через X3DH если её
    /// ещё нет. Это основной метод, который будет вызывать
    /// network/dispatcher.rs перед тем как onion-обернуть пакет.
    pub async fn encrypt_for(
        &self,
        peer: &UserId,
        plaintext: &[u8],
    ) -> Result<EncryptedEnvelope> {
        // `Some(..)` только если ЭТОТ вызов только что завёл сессию с
        // нуля через X3DH (первый контакт) — в таком случае нужно
        // приложить эфемерный ключ/OTPK, чтобы получатель мог поднять
        // такую же сессию ответчиком (см. accept_incoming_session). Если
        // сессия уже существовала (в памяти, восстановлена из стораджа,
        // или это уже не первое сообщение той же сессии) — None, потому
        // что получатель её либо уже принял на первом сообщении, либо
        // сам её инициировал.
        let session_init = self.ensure_session_as_initiator(peer).await?;

        let id = SessionId::for_peer(peer);
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&id)
            .ok_or_else(|| MessengerError::NoSession(peer.clone()))?;

        let mut envelope = session.encrypt(plaintext)?;
        self.persist(session).await?;

        // Штампуем отправителя и подписываем ПОСЛЕ шифрования, но до того
        // как envelope покинет этот процесс: ratchet.rs ничего не знает
        // про identity, поэтому эти два поля — забота SessionManager.
        envelope.sender_id = self.my_identity.user_id.clone();
        envelope.session_init = session_init;
        let to_sign = envelope.signable_bytes();
        envelope.sender_signature = self.my_identity.sign(&to_sign).to_bytes().to_vec();

        Ok(envelope)
    }

    /// Расшифровывает входящий envelope. Если сессии ещё нет и envelope
    /// несёт `session_init` — это первое сообщение нового собеседника:
    /// поднимаем сессию как ответчик (Bob) через `accept_incoming_session`
    /// ПЕРЕД тем как пытаться расшифровать. Раньше на этом месте была
    /// просто ошибка `NoSession` (первое сообщение от незнакомца молча
    /// дропалось выше по стеку, в dispatcher.rs) — X3DH-бутстрап был
    /// реализован (accept_incoming_session существовал), но его
    /// физически некому и нечем было вызвать: не было канала, по
    /// которому эфемерный ключ инициатора доходил бы досюда. Теперь этот
    /// канал — `EncryptedEnvelope::session_init`.
    ///
    /// Порядок важен: подпись проверяется ДО того как тратится ключ
    /// ratchet-цепочки на попытку расшифровки — так подделанный или
    /// повреждённый пакет от чужого identity-ключа отбрасывается, не
    /// сжигая ключ, который был бы нужен для настоящего следующего
    /// сообщения от peer.
    pub async fn decrypt_from(
        &self,
        peer: &UserId,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>> {
        if &envelope.sender_id != peer {
            return Err(MessengerError::SenderMismatch {
                claimed: envelope.sender_id.clone(),
                expected: peer.clone(),
            });
        }

        let verifying_key = self
            .identity_source
            .fetch_identity_key(peer)
            .await
            .map_err(|_| MessengerError::IdentityKeyNotFound(peer.clone()))?;

        let to_verify = envelope.signable_bytes();
        if !Identity::verify_bytes(&verifying_key, &to_verify, &envelope.sender_signature) {
            return Err(MessengerError::InvalidMessageSignature(peer.clone()));
        }

        let id = SessionId::for_peer(peer);

        let has_session = { self.sessions.read().await.contains_key(&id) };
        if !has_session {
            if let Some(init) = &envelope.session_init {
                // Подпись уже проверена выше, так что init — от того, за
                // кого себя выдаёт peer. accept_incoming_session сама
                // молча не-op'ается, если сессия уже была заведена
                // конкурентным вызовом/дублем этого же первого пакета.
                self.accept_incoming_session(peer.clone(), init).await?;
            }
            // Если session_init нет и сессии тоже нет — это НЕ первое
            // сообщение (обычный ratchet-пакет от собеседника, с которым
            // сессия либо никогда не поднималась, либо была эвиктнута) —
            // ниже это законно упадёт в NoSession, а не будет тихо
            // дропнуто без объяснения.
        }

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&id)
            .ok_or_else(|| MessengerError::NoSession(peer.clone()))?;

        let plaintext = session.decrypt(envelope)?;
        self.persist(session).await?;
        Ok(plaintext)
    }

    /// Принимает первое X3DH-сообщение от нового собеседника и заводит
    /// сессию как ответчик (Bob). Вызывается изнутри `decrypt_from`,
    /// когда приходит envelope с непустым `session_init` и сессии с этим
    /// peer ещё нет.
    async fn accept_incoming_session(&self, peer: UserId, init: &SessionInit) -> Result<()> {
        let id = SessionId::for_peer(&peer);
        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(&id) {
                // Гонка: два "первых сообщения" (например ретрансляция
                // недоставленного) обработались почти одновременно.
                // Сессия уже поднята — это не ошибка, продолжаем ею
                // пользоваться, а не отклоняем валидное сообщение.
                return Ok(());
            }
        }

        let their_ephemeral_public = PublicKey::from(init.ephemeral_key);

        // X3DH identity-ключ (X25519, НЕ ed25519-подпись) собеседника —
        // берём из его же опубликованного PreKeyBundle тем же
        // bundle_source, которым инициатор пользуется для нас самих
        // (см. ensure_session_as_initiator). sender_signature уже
        // проверен в decrypt_from по отдельному ed25519-ключу, так что
        // здесь достаточно самого бандла — не нужно ещё раз проверять
        // подлинность личности peer, только достать нужный ключ.
        let their_bundle = self.bundle_source.fetch_bundle(&peer).await?;

        // Если инициатор указал one-time prekey — найти и вычеркнуть его
        // приватную половину из своего пула (forward secrecy: ключ
        // используется максимум один раз). Отсутствие ключа в пуле не
        // обязательно означает атаку — см. race-condition оговорку у
        // `one_time_prekeys` — поэтому просто продолжаем без DH4 вместо
        // того чтобы отклонять всю сессию.
        let our_one_time_prekey = match init.one_time_prekey_public {
            Some(pub_bytes) => {
                let mut pool = self.one_time_prekeys.write().await;
                pool.remove(&pub_bytes)
            }
            None => None,
        };

        let x3dh = X3dhSession::respond(
            &self.x3dh_identity,
            &self.our_signed_prekey,
            our_one_time_prekey.as_ref(),
            &their_bundle.identity_key,
            &their_ephemeral_public,
        );

        let session = Session::new(peer, SessionOrigin::Accepted, x3dh.shared_secret);
        self.persist(&session).await?;

        let mut sessions = self.sessions.write().await;
        sessions.insert(id, session);
        Ok(())
    }

    /// Если сессии с peer нет в памяти — сначала пробуем поднять из
    /// персистентного стораджа (рестарт процесса), и только если там
    /// тоже пусто — инициируем новую через X3DH (первый контакт).
    ///
    /// Возвращает `Some(SessionInit)` ТОЛЬКО если эта сессия только что
    /// была создана заново прямо в этом вызове — это ровно тот момент,
    /// когда собеседник ещё не знает про сессию и должен получить
    /// эфемерный ключ/OTPK-id в первом же исходящем сообщении (см.
    /// `encrypt_for`). Во всех остальных случаях (сессия уже была в
    /// памяти или восстановлена из стораджа) — `None`.
    async fn ensure_session_as_initiator(&self, peer: &UserId) -> Result<Option<SessionInit>> {
        let id = SessionId::for_peer(peer);

        {
            let sessions = self.sessions.read().await;
            if sessions.contains_key(&id) {
                return Ok(None);
            }
        }

        if let Some(restored) = self.store.load(&id).await? {
            let mut sessions = self.sessions.write().await;
            sessions.insert(id, restored);
            return Ok(None);
        }

        // Первый контакт: тянем prekey bundle из DHT и инициируем X3DH.
        let bundle = self.bundle_source.fetch_bundle(peer).await?;
        self.verify_bundle_signature(peer, &bundle).await?;

        let (x3dh, our_ephemeral_public) = X3dhSession::initiate(&self.x3dh_identity, &bundle);
        let session_init = SessionInit {
            ephemeral_key: our_ephemeral_public.to_bytes(),
            one_time_prekey_public: bundle.one_time_prekey.map(|k| k.to_bytes()),
        };

        let session = Session::new(peer.clone(), SessionOrigin::Initiated, x3dh.shared_secret);
        self.persist(&session).await?;

        let mut sessions = self.sessions.write().await;
        sessions.insert(id, session);
        Ok(Some(session_init))
    }

    /// Проверяет, что signed_prekey в бандле подписан ed25519 identity-ключом
    /// собеседника — без этого MITM через скомпрометированный DHT-узел может
    /// подсунуть свой X25519-ключ вместо настоящего, и X3DH даст нападающему
    /// общий секрет вместо реального собеседника. Это ровно та защита, ради
    /// которой в Signal X3DH существует "signed prekey".
    ///
    /// signed_prekey_signature покрывает только signed_prekey.as_bytes()
    /// (Signal-семантика — см. record.rs::PreKeyBundleRecordBuilder::build).
    async fn verify_bundle_signature(&self, peer: &UserId, bundle: &PreKeyBundle) -> Result<()> {
        let verifying_key = self
            .identity_source
            .fetch_identity_key(peer)
            .await
            .map_err(|_| MessengerError::IdentityKeyNotFound(peer.clone()))?;

        if !Identity::verify_bytes(
            &verifying_key,
            bundle.signed_prekey.as_bytes(),
            &bundle.signed_prekey_signature,
        ) {
            return Err(MessengerError::InvalidPreKeySignature(peer.clone()));
        }
        Ok(())
    }

    async fn persist(&self, session: &Session) -> Result<()> {
        self.store.save(session).await
    }

    /// Удаляет протухшие сессии из памяти (не из персистентного
    /// стораджа — те остаются на диске на случай что собеседник
    /// объявится через полгода, тогда просто перезагрузим).
    /// Вызывается периодически из services/background.rs.
    pub async fn evict_stale(&self, max_idle_secs: u64) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, s| !s.is_stale(max_idle_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::x3dh::PreKeyBundle;
    use rand_core::OsRng;
    use std::sync::Mutex;

    struct FakeStore {
        data: Mutex<HashMap<SessionId, [u8; 32]>>,
    }

    #[async_trait::async_trait]
    impl SessionStore for FakeStore {
        async fn save(&self, session: &Session) -> Result<()> {
            self.data
                .lock()
                .unwrap()
                .insert(session.id.clone(), [0u8; 32]);
            Ok(())
        }
        async fn load(&self, _id: &SessionId) -> Result<Option<Session>> {
            Ok(None) // упрощённо для теста: не тестируем restore здесь
        }
    }

    struct FakeBundleSource {
        bob_identity: StaticSecret,
        bob_signed_prekey: StaticSecret,
        /// `None` в тестах без X3DH-бутстрапа, `Some` в тестах где
        /// инициатор (Алиса) должна указать OTPK Боба в `session_init`.
        bob_one_time_prekey: Option<PublicKey>,
        /// ed25519 ключ которым подписан signed_prekey (Signal-семантика).
        /// `None` только для тестов, которые НЕ вызывают verify_bundle_signature
        /// (т.е. сессия создаётся вручную, минуя X3DH).
        signing_key: Option<ed25519_dalek::SigningKey>,
    }

    #[async_trait::async_trait]
    impl PreKeyBundleSource for FakeBundleSource {
        async fn fetch_bundle(&self, _peer: &UserId) -> Result<PreKeyBundle> {
            let signed_prekey_pub = PublicKey::from(&self.bob_signed_prekey);
            let sig = if let Some(sk) = &self.signing_key {
                use ed25519_dalek::Signer;
                // Signal-семантика: подписываем только байты signed_prekey-ключа.
                sk.sign(signed_prekey_pub.as_bytes()).to_bytes().to_vec()
            } else {
                // Недостижимо в тестах, которые проходят через verify_bundle_signature,
                // т.к. там signing_key обязателен. Для тестов без X3DH — Ok.
                vec![0u8; 64]
            };
            Ok(PreKeyBundle {
                identity_key: PublicKey::from(&self.bob_identity),
                signed_prekey: signed_prekey_pub,
                signed_prekey_signature: sig,
                one_time_prekey: self.bob_one_time_prekey,
            })
        }
    }

    /// В тестах у нас всегда ровно два известных участника (Alice/Bob),
    /// так что просто держим их verifying key в мапе вместо похода в DHT.
    struct FakeIdentitySource {
        keys: std::collections::HashMap<UserId, ed25519_dalek::VerifyingKey>,
    }

    #[async_trait::async_trait]
    impl PeerIdentitySource for FakeIdentitySource {
        async fn fetch_identity_key(&self, peer: &UserId) -> Result<ed25519_dalek::VerifyingKey> {
            self.keys
                .get(peer)
                .copied()
                .ok_or_else(|| MessengerError::IdentityKeyNotFound(peer.clone()))
        }
    }

    /// `bob_signing_key` — ed25519-ключ, которым подписан signed_prekey
    /// в FakeBundleSource. Обязан быть `Some` для тестов, где инициатор
    /// (Алиса) вызывает `encrypt_for` → `ensure_session_as_initiator` →
    /// `verify_bundle_signature` (проверяет реальную ed25519-подпись).
    /// Может быть `None` только если сессия создаётся вручную (минуя X3DH).
    fn make_manager(
        my_identity: Arc<Identity>,
        peer_keys: std::collections::HashMap<UserId, ed25519_dalek::VerifyingKey>,
        bob_identity: StaticSecret,
        bob_signed_prekey: StaticSecret,
        bob_signing_key: Option<ed25519_dalek::SigningKey>,
    ) -> SessionManager {
        let store = Arc::new(FakeStore {
            data: Mutex::new(HashMap::new()),
        });
        let bundle_source = Arc::new(FakeBundleSource {
            bob_identity,
            bob_signed_prekey,
            bob_one_time_prekey: None,
            signing_key: bob_signing_key,
        });
        let identity_source = Arc::new(FakeIdentitySource { keys: peer_keys });
        let x3dh_identity = StaticSecret::random_from_rng(OsRng);
        let our_signed_prekey = StaticSecret::random_from_rng(OsRng);
        SessionManager::new(
            store,
            x3dh_identity,
            our_signed_prekey,
            Vec::new(),
            bundle_source,
            my_identity,
            identity_source,
        )
    }

    #[tokio::test]
    async fn initiator_bootstraps_session_via_x3dh() {
        let bob_x3dh_identity = StaticSecret::random_from_rng(OsRng);
        let bob_signed_prekey = StaticSecret::random_from_rng(OsRng);
        let bob_signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let alice = Arc::new(Identity::generate());

        // verify_bundle_signature проверяет реальную ed25519-подпись через
        // identity_source — кладём verifying key Боба в таблицу Алисы.
        let mut peer_keys = HashMap::new();
        peer_keys.insert("bob".to_string(), bob_signing_key.verifying_key());

        let manager = make_manager(
            alice,
            peer_keys,
            bob_x3dh_identity,
            bob_signed_prekey,
            Some(bob_signing_key),
        );

        let envelope = manager.encrypt_for(&"bob".to_string(), b"hello").await;
        assert!(envelope.is_ok());
        let envelope = envelope.unwrap();
        assert!(!envelope.sender_signature.is_empty());
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected_on_decrypt() {
        let bob_identity_dh = StaticSecret::random_from_rng(OsRng);
        let bob_signed_prekey = StaticSecret::random_from_rng(OsRng);

        let alice = Arc::new(Identity::generate());
        let bob = Arc::new(Identity::generate());

        // Обе стороны должны знать identity-ключ друг друга, чтобы
        // проверять входящие подписи.
        let mut alice_knows: std::collections::HashMap<UserId, ed25519_dalek::VerifyingKey> =
            std::collections::HashMap::new();
        alice_knows.insert(bob.user_id.clone(), bob.verifying_key);
        let mut bob_knows: std::collections::HashMap<UserId, ed25519_dalek::VerifyingKey> =
            std::collections::HashMap::new();
        bob_knows.insert(alice.user_id.clone(), alice.verifying_key);

        let alice_mgr = make_manager(
            alice.clone(),
            alice_knows,
            bob_identity_dh.clone(),
            bob_signed_prekey.clone(),
            None, // сессия создаётся вручную ниже — X3DH не вызывается
        );
        let bob_mgr = make_manager(bob.clone(), bob_knows, bob_identity_dh, bob_signed_prekey, None);

        // Прямая сессия между alice_mgr и bob_mgr вручную (минуя X3DH,
        // чтобы тест был про подпись, а не про X3DH-бутстрап).
        let shared_secret = [42u8; 32];
        {
            let mut sessions = alice_mgr.sessions.write().await;
            sessions.insert(
                SessionId::for_peer(&bob.user_id),
                Session::new(bob.user_id.clone(), SessionOrigin::Initiated, shared_secret),
            );
        }
        {
            let mut sessions = bob_mgr.sessions.write().await;
            sessions.insert(
                SessionId::for_peer(&alice.user_id),
                Session::new(alice.user_id.clone(), SessionOrigin::Accepted, shared_secret),
            );
        }

        let mut sessions = alice_mgr.sessions.write().await;
        let session = sessions.get_mut(&SessionId::for_peer(&bob.user_id)).unwrap();
        let mut envelope = session.encrypt(b"hi bob").unwrap();
        drop(sessions);
        envelope.sender_id = alice.user_id.clone();
        let to_sign = envelope.signable_bytes();
        envelope.sender_signature = alice.sign(&to_sign).to_bytes().to_vec();

        // Честное сообщение проходит.
        let plaintext = bob_mgr.decrypt_from(&alice.user_id, &envelope).await;
        assert_eq!(plaintext.unwrap(), b"hi bob");

        // А теперь та же связка, но с чужой подписью (bob подписывает
        // сообщение, которое якобы от alice) — должно быть отвергнуто.
        let mut forged = envelope.clone();
        forged.counter += 1; // другой counter, чтобы не упереться в replay-проверку раньше подписи
        let bogus_sig = bob.sign(&forged.signable_bytes());
        forged.sender_signature = bogus_sig.to_bytes().to_vec();
        let result = bob_mgr.decrypt_from(&alice.user_id, &forged).await;
        assert!(matches!(result, Err(MessengerError::InvalidMessageSignature(_))));
    }

    /// Раньше первое сообщение от незнакомца заканчивалось NoSession и
    /// молча дропалось выше по стеку (dispatcher.rs) — `session_init`
    /// было негде передать, а `accept_incoming_session` существовал, но
    /// не имел вызывающего кода. Этот тест — тот самый сценарий "chuzhoy
    /// chelovek pishet vpervые", который раньше был невозможен целиком.
    #[tokio::test]
    async fn stranger_first_message_bootstraps_responder_session_via_x3dh() {
        let alice = Arc::new(Identity::generate());
        let bob = Arc::new(Identity::generate());

        let bob_x3dh_identity = StaticSecret::random_from_rng(OsRng);
        let bob_signed_prekey = StaticSecret::random_from_rng(OsRng);
        let bob_otpk = StaticSecret::random_from_rng(OsRng);
        let bob_otpk_public = PublicKey::from(&bob_otpk);

        let mut alice_knows: std::collections::HashMap<UserId, ed25519_dalek::VerifyingKey> =
            std::collections::HashMap::new();
        alice_knows.insert(bob.user_id.clone(), bob.verifying_key);
        let mut bob_knows: std::collections::HashMap<UserId, ed25519_dalek::VerifyingKey> =
            std::collections::HashMap::new();
        bob_knows.insert(alice.user_id.clone(), alice.verifying_key);

        // Alice видит опубликованный бандл Боба (включая OTPK) через DHT.
        // verify_bundle_signature проверяет реальную ed25519-подпись —
        // достаём signing key из bob.export_secret_bytes().
        let bob_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&bob.export_secret_bytes());

        let alice_mgr = SessionManager::new(
            Arc::new(FakeStore {
                data: Mutex::new(HashMap::new()),
            }),
            StaticSecret::random_from_rng(OsRng),
            StaticSecret::random_from_rng(OsRng),
            Vec::new(),
            Arc::new(FakeBundleSource {
                bob_identity: bob_x3dh_identity.clone(),
                bob_signed_prekey: bob_signed_prekey.clone(),
                bob_one_time_prekey: Some(bob_otpk_public),
                signing_key: Some(bob_signing_key),
            }),
            alice.clone(),
            Arc::new(FakeIdentitySource { keys: alice_knows }),
        );

        // Bob никогда не выступает инициатором в этом тесте — его
        // bundle_source не должен вызываться, но конструктору он всё
        // равно нужен.
        let bob_mgr = SessionManager::new(
            Arc::new(FakeStore {
                data: Mutex::new(HashMap::new()),
            }),
            bob_x3dh_identity,
            bob_signed_prekey,
            vec![bob_otpk],
            Arc::new(FakeBundleSource {
                bob_identity: StaticSecret::random_from_rng(OsRng),
                bob_signed_prekey: StaticSecret::random_from_rng(OsRng),
                bob_one_time_prekey: None,
                signing_key: None, // bundle_source Боба не вызывается в этом тесте
            }),
            bob.clone(),
            Arc::new(FakeIdentitySource { keys: bob_knows }),
        );

        // Первое сообщение: Алиса поднимает сессию через X3DH, envelope
        // обязан нести session_init.
        let envelope = alice_mgr
            .encrypt_for(&bob.user_id, b"yo stranger")
            .await
            .unwrap();
        assert!(
            envelope.session_init.is_some(),
            "первое сообщение новой сессии должно нести X3DH session_init"
        );

        // Боб раньше не знал про Алису вообще — decrypt_from должен сам
        // поднять сессию как ответчик и расшифровать этим же вызовом.
        let plaintext = bob_mgr
            .decrypt_from(&alice.user_id, &envelope)
            .await
            .unwrap();
        assert_eq!(plaintext, b"yo stranger");

        // Второе сообщение в уже установленной сессии НЕ должно повторно
        // нести session_init — Боб уже принял сессию на первом сообщении.
        let envelope2 = alice_mgr
            .encrypt_for(&bob.user_id, b"still here")
            .await
            .unwrap();
        assert!(envelope2.session_init.is_none());
        let plaintext2 = bob_mgr
            .decrypt_from(&alice.user_id, &envelope2)
            .await
            .unwrap();
        assert_eq!(plaintext2, b"still here");

        // OTPK потрачен ровно один раз (forward secrecy) — пул у Боба пуст.
        assert!(bob_mgr.one_time_prekeys.read().await.is_empty());
    }
}
