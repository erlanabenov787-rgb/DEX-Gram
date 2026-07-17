//! Локальное хранилище. Всё что тут лежит — уже расшифрованные данные
//! ИЛИ ключи, поэтому сам файл базы должен лежать в защищённой ОС
//! директории приложения (на Android — internal storage, недоступно
//! другим приложениям без root).

use rusqlite::{params, Connection, Result as SqlResult};

/// `conn` — за `std::sync::Mutex`, а не голым полем: `rusqlite::Connection`
/// умышленно реализует только `Send`, не `Sync` (см. подробный
/// комментарий у DbPeerIdentitySource ниже) — то есть `&Database` из
/// двух потоков одновременно в принципе не должно компилироваться без
/// этого. session_store.rs и mailbox_store.rs в этом же крейте уже
/// используют этот же паттерн (`conn: Mutex<Connection>`) — раньше
/// именно этот файл был единственным исключением, из-за чего
/// `Arc<Database>` (см. network/p2p.rs, network/relay/scoring.rs) не
/// мог быть ни Send, ни Sync, и не компилировался бы, будучи реально
/// зашаренным между задачами (что происходит, когда NodeHandle
/// спавнится в отдельный tokio-таск, как это делает src-tauri/src/lib.rs).
pub struct Database {
    conn: std::sync::Mutex<Connection>,
}

/// Adapter: реализует `session::manager::PeerIdentitySource` поверх
/// локальной таблицы `contacts`. DHT-путь
/// (`network::dht::lookup::DhtLookupSource`) теперь реально подключён к
/// event loop-у (см. `dht_lookup_rx` в p2p.rs), но это отдельный trait
/// (`PreKeyBundleSource`, не `PeerIdentitySource`) — специально для
/// проверки подписи X3DH-бандла. Для проверки подписи ВХОДЯЩИХ
/// СООБЩЕНИЙ (что и есть PeerIdentitySource) намеренно оставляем
/// локальную базу контактов основным источником: она не требует, чтобы
/// собеседник был online именно в момент проверки, раз пользователь уже
/// один раз вручную сверил и добавил publicKeyHex через add_contact.
///
/// ВАЖНО про Send/Sync: `rusqlite::Connection` умышленно реализует
/// только `Send`, но не `Sync` (это в документации rusqlite — так они
/// гарантируют потокобезопасность на этапе компиляции, не полагаясь на
/// SQLite serialized-mode). А `PeerIdentitySource: Send + Sync` (см.
/// session/manager.rs, там используется как `Arc<dyn ...>` — то есть
/// шарится между потоками/тасками). Голый `Arc<Database>` этому не
/// удовлетворяет: `Arc<T>` требует `T: Send + Sync` для *обоих* своих
/// impl-ов Send/Sync разом, так что `Arc<Database>` не является ни тем,
/// ни другим, если `Database` не Sync. Поэтому здесь — отдельный
/// std::sync::Mutex вокруг Database, а не голый Arc: он берётся только
/// на время одного синхронного запроса, никогда не держится через
/// .await, так что не мешает async runtime.
pub struct DbPeerIdentitySource {
    db: std::sync::Mutex<Database>,
}

impl DbPeerIdentitySource {
    /// Открывает собственное соединение с той же базой — соединения в
    /// rusqlite дешёвые, а раздельное соединение проще чем шарить один
    /// Connection между этим адаптером и остальным приложением через
    /// ещё один слой блокировок.
    pub fn new(db: Database) -> Self {
        Self {
            db: std::sync::Mutex::new(db),
        }
    }
}

#[async_trait::async_trait]
impl crate::session::manager::PeerIdentitySource for DbPeerIdentitySource {
    async fn fetch_identity_key(
        &self,
        peer: &crate::identity::UserId,
    ) -> crate::errors::Result<ed25519_dalek::VerifyingKey> {
        let bytes = {
            let db = self.db.lock().expect("DbPeerIdentitySource mutex poisoned");
            db.get_contact_public_key(peer)
                .map_err(crate::errors::MessengerError::Storage)?
        };
        let bytes = bytes.ok_or_else(|| crate::errors::MessengerError::IdentityKeyNotFound(peer.clone()))?;

        crate::identity::Identity::verifying_key_from_bytes(&bytes)
            .ok_or_else(|| crate::errors::MessengerError::IdentityKeyNotFound(peer.clone()))
    }
}

impl Database {
    pub fn open(path: &str) -> SqlResult<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn: std::sync::Mutex::new(conn) };
        db.init_schema()?;
        Ok(db)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> SqlResult<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn: std::sync::Mutex::new(conn) };
        db.init_schema()?;
        Ok(db)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("Database mutex poisoned (a previous call must have panicked while holding it)")
    }

    fn init_schema(&self) -> SqlResult<()> {
        self.conn().execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS contacts (
                user_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                public_key BLOB NOT NULL,
                added_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ratchet_state (
                contact_user_id TEXT PRIMARY KEY,
                chain_key BLOB NOT NULL,
                send_counter INTEGER NOT NULL,
                recv_counter INTEGER NOT NULL,
                FOREIGN KEY (contact_user_id) REFERENCES contacts(user_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_user_id TEXT NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('sent','received')),
                plaintext TEXT NOT NULL,
                sent_at INTEGER NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (contact_user_id) REFERENCES contacts(user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_contact
                ON messages(contact_user_id, sent_at);

            CREATE TABLE IF NOT EXISTS local_identity (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                secret_key BLOB NOT NULL,
                user_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            -- Отдельно от local_identity: identity выше — ed25519
            -- (подписи), эти два ключа — x25519 (X3DH Diffie-Hellman).
            -- Персистентность нужна по той же причине, что и у
            -- local_identity: без неё опубликованный в DHT PreKeyBundle
            -- каждый рестарт ссылался бы на уже мёртвый identity-ключ, и
            -- никто не смог бы завершить X3DH с этим бандлом. One-time
            -- prekeys НЕ хранятся тут намеренно — они одноразовые и
            -- перегенерируются батчем при каждом старте (см.
            -- constants::PREKEY_BATCH_SIZE), персистить их бессмысленно.
            CREATE TABLE IF NOT EXISTS local_x3dh_keys (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                x3dh_identity_secret BLOB NOT NULL,
                signed_prekey_secret BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            -- Onion-ключ (X25519) этого узла, если он выступает relay
            -- (cfg.is_relay = true) в чьей-то static_relays-конфигурации.
            -- РАНЬШЕ (см. network/p2p.rs) этот секрет генерировался
            -- заново случайно на КАЖДОМ старте — значит любой узел,
            -- прописавший нас в своём cfg.static_relays с нашим
            -- onion_public_key_hex, после нашего первого рестарта
            -- получал бы неразрешимый onion-слой (наш новый секрет не
            -- матчится с их старым публичным ключом). Тот же паттерн
            -- персистентности, что и local_x3dh_keys выше.
            CREATE TABLE IF NOT EXISTS local_onion_key (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                onion_secret BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS known_relays (
                relay_id TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                reputation_score REAL NOT NULL DEFAULT 0.0,
                first_seen_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL
            );
            "#,
        )
    }

    pub fn add_contact(&self, user_id: &str, display_name: &str, public_key: &[u8]) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO contacts (user_id, display_name, public_key, added_at)
             VALUES (?1, ?2, ?3, strftime('%s','now'))",
            params![user_id, display_name, public_key],
        )?;
        Ok(())
    }

    pub fn save_message(
        &self,
        contact_user_id: &str,
        direction: &str,
        plaintext: &str,
    ) -> SqlResult<()> {
        self.conn().execute(
            "INSERT INTO messages (contact_user_id, direction, plaintext, sent_at)
             VALUES (?1, ?2, ?3, strftime('%s','now'))",
            params![contact_user_id, direction, plaintext],
        )?;
        Ok(())
    }

    pub fn get_history(&self, contact_user_id: &str, limit: u32) -> SqlResult<Vec<(String, String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT direction, plaintext, sent_at FROM messages
             WHERE contact_user_id = ?1
             ORDER BY sent_at DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![contact_user_id, limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect()
    }

    /// Сохраняет приватный ключ локально. CHECK(id=0) в схеме гарантирует
    /// что в базе всегда максимум ОДНА identity — это персональный
    /// клиент, не мультиаккаунт-хранилище.
    pub fn save_identity(&self, secret_key: &[u8; 32], user_id: &str) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO local_identity (id, secret_key, user_id, created_at)
             VALUES (0, ?1, ?2, strftime('%s','now'))",
            params![secret_key.as_slice(), user_id],
        )?;
        Ok(())
    }

    /// Возвращает (secret_key, user_id) если identity уже была создана
    /// раньше — используется при старте нода, чтобы не генерить новый
    /// UserID при каждом перезапуске.
    pub fn load_identity(&self) -> SqlResult<Option<([u8; 32], String)>> {
        let result = self.conn().query_row(
            "SELECT secret_key, user_id FROM local_identity WHERE id = 0",
            [],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                let user_id: String = row.get(1)?;
                Ok((bytes, user_id))
            },
        );

        match result {
            Ok((bytes, user_id)) => {
                let mut key = [0u8; 32];
                if bytes.len() == 32 {
                    key.copy_from_slice(&bytes);
                    Ok(Some((key, user_id)))
                } else {
                    Ok(None) // повреждённые данные — считаем что identity нет
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Сохраняет X3DH-ключи (identity + signed prekey) локально.
    /// CHECK(id=0) — та же логика, что у save_identity: одна личность на
    /// клиента, не мультиаккаунт-хранилище.
    pub fn save_x3dh_keys(
        &self,
        x3dh_identity_secret: &[u8; 32],
        signed_prekey_secret: &[u8; 32],
    ) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO local_x3dh_keys (id, x3dh_identity_secret, signed_prekey_secret, created_at)
             VALUES (0, ?1, ?2, strftime('%s','now'))",
            params![x3dh_identity_secret.as_slice(), signed_prekey_secret.as_slice()],
        )?;
        Ok(())
    }

    /// Возвращает (x3dh_identity_secret, signed_prekey_secret), если они
    /// уже были созданы раньше — используется при старте нода, чтобы
    /// PreKeyBundle, опубликованный в прошлый раз, не стал мгновенно
    /// мёртвым при каждом перезапуске.
    pub fn load_x3dh_keys(&self) -> SqlResult<Option<([u8; 32], [u8; 32])>> {
        let result = self.conn().query_row(
            "SELECT x3dh_identity_secret, signed_prekey_secret FROM local_x3dh_keys WHERE id = 0",
            [],
            |row| {
                let identity_bytes: Vec<u8> = row.get(0)?;
                let prekey_bytes: Vec<u8> = row.get(1)?;
                Ok((identity_bytes, prekey_bytes))
            },
        );

        match result {
            Ok((identity_bytes, prekey_bytes)) => {
                if identity_bytes.len() != 32 || prekey_bytes.len() != 32 {
                    return Ok(None); // повреждённые данные — считаем что ключей нет
                }
                let mut identity_key = [0u8; 32];
                let mut prekey_key = [0u8; 32];
                identity_key.copy_from_slice(&identity_bytes);
                prekey_key.copy_from_slice(&prekey_bytes);
                Ok(Some((identity_key, prekey_key)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Сохраняет onion-секрет (X25519) узла, используется только когда
    /// cfg.is_relay = true — иначе он никому не нужен, но хранить не вредно.
    pub fn save_onion_key(&self, onion_secret: &[u8; 32]) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO local_onion_key (id, onion_secret, created_at)
             VALUES (0, ?1, strftime('%s','now'))",
            params![onion_secret.as_slice()],
        )?;
        Ok(())
    }

    /// Возвращает ранее сохранённый onion-секрет, если он есть — используется
    /// при старте нода вместо генерации нового случайного (см. комментарий
    /// у CREATE TABLE local_onion_key: без этого relay-роль ломается при
    /// каждом рестарте для всех, кто прописал наш старый публичный ключ).
    pub fn load_onion_key(&self) -> SqlResult<Option<[u8; 32]>> {
        let result = self.conn().query_row(
            "SELECT onion_secret FROM local_onion_key WHERE id = 0",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match result {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Ok(None); // повреждённые данные — считаем что ключа нет
                }
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&bytes);
                Ok(Some(secret))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Список контактов для UI — сортировка на фронте, тут просто всё отдаём.
    pub fn list_contacts(&self) -> SqlResult<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT user_id, display_name FROM contacts ORDER BY display_name")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    /// Публичный ключ контакта (ed25519 verifying key, как его ввёл
    /// пользователь через add_contact) — нужен чтобы проверить подпись
    /// на входящих сообщениях от него. `None`, если контакта нет.
    pub fn get_contact_public_key(&self, user_id: &str) -> SqlResult<Option<Vec<u8>>> {
        let result = self.conn().query_row(
            "SELECT public_key FROM contacts WHERE user_id = ?1",
            params![user_id],
            |row| row.get::<_, Vec<u8>>(0),
        );
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn upsert_relay_reputation(&self, relay_id: &str, address: &str, score_delta: f64) -> SqlResult<()> {
        self.conn().execute(
            "INSERT INTO known_relays (relay_id, address, reputation_score, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, strftime('%s','now'), strftime('%s','now'))
             ON CONFLICT(relay_id) DO UPDATE SET
                reputation_score = reputation_score + ?3,
                last_seen_at = strftime('%s','now')",
            params![relay_id, address, score_delta],
        )?;
        Ok(())
    }

    /// Отдаёт relay отсортированные по репутации — для выбора маршрута
    /// (проверенные чаще, новые реже, но не игнорируются совсем).
    pub fn best_relays(&self, limit: u32) -> SqlResult<Vec<(String, String, f64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT relay_id, address, reputation_score FROM known_relays
             ORDER BY reputation_score DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_and_message_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        db.add_contact("user123", "Амир", b"fakepubkey").unwrap();
        db.save_message("user123", "sent", "привет бро").unwrap();

        let history = db.get_history("user123", 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].1, "привет бро");
    }

    #[test]
    fn relay_reputation_accumulates() {
        let db = Database::open_in_memory().unwrap();
        db.upsert_relay_reputation("relay1", "1.2.3.4:9000", 1.0).unwrap();
        db.upsert_relay_reputation("relay1", "1.2.3.4:9000", 1.0).unwrap();

        let best = db.best_relays(10).unwrap();
        assert_eq!(best[0].2, 2.0);
    }

    #[test]
    fn identity_persists_across_reopen() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.load_identity().unwrap().is_none());

        let secret = [9u8; 32];
        db.save_identity(&secret, "myUserId123").unwrap();

        let loaded = db.load_identity().unwrap().unwrap();
        assert_eq!(loaded.0, secret);
        assert_eq!(loaded.1, "myUserId123");
    }

    #[test]
    fn x3dh_keys_persist_across_reopen() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.load_x3dh_keys().unwrap().is_none());

        let identity_secret = [7u8; 32];
        let prekey_secret = [8u8; 32];
        db.save_x3dh_keys(&identity_secret, &prekey_secret).unwrap();

        let loaded = db.load_x3dh_keys().unwrap().unwrap();
        assert_eq!(loaded.0, identity_secret);
        assert_eq!(loaded.1, prekey_secret);
    }
}
