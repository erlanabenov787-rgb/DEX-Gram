//! Локальное хранилище. Всё что тут лежит — уже расшифрованные данные
//! ИЛИ ключи, поэтому сам файл базы должен лежать в защищённой ОС
//! директории приложения (на Android — internal storage, недоступно
//! другим приложениям без root).

use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};

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

            -- Произвольные настройки приложения (key-value).
            -- Используется для хранения bootstrap_url и других
            -- пользовательских настроек между запусками.
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
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

    pub fn list_contacts(&self) -> SqlResult<Vec<(String, String)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT user_id, display_name FROM contacts ORDER BY added_at DESC",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    pub fn get_history(
        &self,
        contact_user_id: &str,
        limit: u32,
    ) -> SqlResult<Vec<(String, String, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT direction, plaintext, sent_at FROM messages
             WHERE contact_user_id = ?1
             ORDER BY sent_at ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![contact_user_id, limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect()
    }

    pub fn save_identity(&self, secret_bytes: &[u8], user_id: &str) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO local_identity (id, secret_key, user_id, created_at)
             VALUES (0, ?1, ?2, strftime('%s','now'))",
            params![secret_bytes, user_id],
        )?;
        Ok(())
    }

    pub fn load_identity(&self) -> SqlResult<Option<(Vec<u8>, String)>> {
        let conn = self.conn();
        let result = conn.query_row(
            "SELECT secret_key, user_id FROM local_identity WHERE id = 0",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save_x3dh_keys(&self, identity_secret: &[u8], prekey_secret: &[u8]) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO local_x3dh_keys (id, x3dh_identity_secret, signed_prekey_secret, created_at)
             VALUES (0, ?1, ?2, strftime('%s','now'))",
            params![identity_secret, prekey_secret],
        )?;
        Ok(())
    }

    pub fn load_x3dh_keys(&self) -> SqlResult<Option<([u8; 32], [u8; 32])>> {
        let conn = self.conn();
        let result = conn.query_row(
            "SELECT x3dh_identity_secret, signed_prekey_secret FROM local_x3dh_keys WHERE id = 0",
            [],
            |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let pk_bytes: Vec<u8> = row.get(1)?;
                Ok((id_bytes, pk_bytes))
            },
        );
        match result {
            Ok((id_bytes, pk_bytes)) => {
                let mut id_arr = [0u8; 32];
                let mut pk_arr = [0u8; 32];
                if id_bytes.len() == 32 && pk_bytes.len() == 32 {
                    id_arr.copy_from_slice(&id_bytes);
                    pk_arr.copy_from_slice(&pk_bytes);
                    Ok(Some((id_arr, pk_arr)))
                } else {
                    Ok(None)
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// cfg.is_relay = true — иначе он никому не нужен, но хранить не вредно.
    pub fn save_onion_key(&self, secret_bytes: &[u8]) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO local_onion_key (id, onion_secret, created_at)
             VALUES (0, ?1, strftime('%s','now'))",
            params![secret_bytes],
        )?;
        Ok(())
    }

    /// у CREATE TABLE local_onion_key: без этого relay-роль ломается при
    /// перезапуске — новый onion ключ не совпадёт с тем, что знают клиенты.
    pub fn load_onion_key(&self) -> SqlResult<Option<[u8; 32]>> {
        let conn = self.conn();
        let result = conn.query_row(
            "SELECT onion_secret FROM local_onion_key WHERE id = 0",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        );
        match result {
            Ok(bytes) => {
                let mut arr = [0u8; 32];
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                    Ok(Some(arr))
                } else {
                    Ok(None)
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Возвращает публичный ключ контакта (ed25519) для проверки подписи
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

    // ── app_settings: key-value хранилище настроек приложения ──────────────

    /// Читает сохранённую настройку по ключу.
    /// Возвращает None если ключ не найден.
    pub fn get_setting(&self, key: &str) -> SqlResult<Option<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT value FROM app_settings WHERE key = ?1")?;
        stmt.query_row(params![key], |row| row.get::<_, String>(0))
            .optional()
    }

    /// Сохраняет или обновляет настройку приложения.
    pub fn set_setting(&self, key: &str, value: &str) -> SqlResult<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Удаляет настройку (например чтобы сбросить bootstrap_url).
    pub fn delete_setting(&self, key: &str) -> SqlResult<()> {
        self.conn().execute(
            "DELETE FROM app_settings WHERE key = ?1",
            params![key],
        )?;
        Ok(())
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
        db.save_identity(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "user1").unwrap();
        let loaded = db.load_identity().unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn app_settings_roundtrip() {
        let db = Database::open_in_memory().unwrap();

        // Чтение несуществующего ключа — None
        assert_eq!(db.get_setting("bootstrap_url").unwrap(), None);

        // Сохранение и чтение
        db.set_setting("bootstrap_url", "http://1.2.3.4:8080").unwrap();
        assert_eq!(
            db.get_setting("bootstrap_url").unwrap(),
            Some("http://1.2.3.4:8080".to_string())
        );

        // Обновление
        db.set_setting("bootstrap_url", "https://new.host:9000").unwrap();
        assert_eq!(
            db.get_setting("bootstrap_url").unwrap(),
            Some("https://new.host:9000".to_string())
        );

        // Удаление
        db.delete_setting("bootstrap_url").unwrap();
        assert_eq!(db.get_setting("bootstrap_url").unwrap(), None);
    }
}
