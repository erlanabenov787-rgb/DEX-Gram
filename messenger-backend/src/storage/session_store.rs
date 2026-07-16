//! Персистентность для session/state.rs. Хранит root_secret зашифрованным
//! на диске (сам SQLite-файл должен лежать в защищённой ОС-директории —
//! это ответственность config/, не этого модуля), плюс метаданные сессии
//! нужные чтобы восстановить Session после рестарта процесса без
//! необходимости заново гонять X3DH.

use async_trait::async_trait;
use rusqlite::{params, Connection};
use std::sync::Mutex;

use crate::crypto::RatchetState;
use crate::errors::Result;
use crate::session::state::{Session, SessionOrigin};
use crate::types::SessionId;

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn save(&self, session: &Session) -> Result<()>;
    async fn load(&self, id: &SessionId) -> Result<Option<Session>>;
}

pub struct SqliteSessionStore {
    conn: Mutex<Connection>,
}

impl SqliteSessionStore {
    pub fn open(conn: Connection) -> Result<Self> {
        // РАНЬШЕ здесь была одна колонка `root_secret BLOB`, в которую
        // save() всегда писал плейсхолдер `[0u8;32]` (см. старый
        // комментарий над save() ниже) — реальное состояние ratchet-а
        // никогда не сохранялось, и load() каждый раз пересобирал сессию
        // через Session::new с нулевыми counter'ами. Это ломало
        // расшифровку входящих сообщений после любого рестарта процесса,
        // как только на цепочке было хотя бы одно сообщение. Теперь
        // храним реальные send/recv половины RatchetState по отдельности
        // (см. crypto::RatchetState / DoubleRatchet::export_state) —
        // разбивка на 4 колонки, а не один BLOB с bincode, чтобы схему
        // было проще читать/чинить руками через `sqlite3` при отладке.
        //
        // ВАЖНО: это ломающая смену схемы (старые строки с колонкой
        // root_secret несовместимы) — приемлемо, т.к. никаких реальных
        // задеплоенных данных ещё нет (pre-release), но стоит иметь в
        // виду при апгрейде уже запущенного узла: старые сессии придётся
        // пересоздать через новый X3DH.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id        TEXT PRIMARY KEY,
                peer              TEXT NOT NULL,
                origin            TEXT NOT NULL,
                send_chain_key    BLOB NOT NULL,
                send_counter      INTEGER NOT NULL,
                recv_chain_key    BLOB NOT NULL,
                recv_counter      INTEGER NOT NULL,
                created_at        INTEGER NOT NULL,
                last_used_at      INTEGER NOT NULL,
                messages_sent     INTEGER NOT NULL,
                messages_received INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn save(&self, session: &Session) -> Result<()> {
        // РАНЬШЕ тут писался плейсхолдер `[0u8;32]` вместо реального
        // состояния ratchet-цепочки (DoubleRatchet не выставлял наружу
        // export_state()) — теперь export_ratchet_state() отдаёт
        // настоящие send/recv ключи+counter'ы, так что ON CONFLICT
        // тоже должен их обновлять (не только метаданные метрик), иначе
        // повторный save() той же сессии после новых сообщений опять
        // писал бы устаревшее состояние при апдейте существующей строки.
        let state = session.export_ratchet_state();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions
                (session_id, peer, origin, send_chain_key, send_counter,
                 recv_chain_key, recv_counter, created_at, last_used_at,
                 messages_sent, messages_received)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(session_id) DO UPDATE SET
                send_chain_key = excluded.send_chain_key,
                send_counter = excluded.send_counter,
                recv_chain_key = excluded.recv_chain_key,
                recv_counter = excluded.recv_counter,
                last_used_at = excluded.last_used_at,
                messages_sent = excluded.messages_sent,
                messages_received = excluded.messages_received",
            params![
                session.id.0,
                session.peer,
                origin_to_str(session.origin),
                &state.send_chain_key[..],
                state.send_counter,
                &state.recv_chain_key[..],
                state.recv_counter,
                session.created_at as i64,
                session.last_used_at as i64,
                session.messages_sent as i64,
                session.messages_received as i64,
            ],
        )?;
        Ok(())
    }

    async fn load(&self, id: &SessionId) -> Result<Option<Session>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT peer, origin, send_chain_key, send_counter, recv_chain_key, recv_counter,
                    created_at, last_used_at, messages_sent, messages_received
             FROM sessions WHERE session_id = ?1",
        )?;

        let mut rows = stmt.query(params![id.0])?;
        if let Some(row) = rows.next()? {
            let peer: String = row.get(0)?;
            let origin_str: String = row.get(1)?;
            let send_chain_key_blob: Vec<u8> = row.get(2)?;
            let send_counter: u32 = row.get(3)?;
            let recv_chain_key_blob: Vec<u8> = row.get(4)?;
            let recv_counter: u32 = row.get(5)?;
            let created_at: i64 = row.get(6)?;
            let last_used_at: i64 = row.get(7)?;
            let messages_sent: i64 = row.get(8)?;
            let messages_received: i64 = row.get(9)?;

            if send_chain_key_blob.len() != 32 || recv_chain_key_blob.len() != 32 {
                return Err(crate::errors::MessengerError::Crypto(
                    "повреждённые данные сессии в БД: send/recv_chain_key не 32 байта".to_string(),
                ));
            }
            let mut send_chain_key = [0u8; 32];
            send_chain_key.copy_from_slice(&send_chain_key_blob);
            let mut recv_chain_key = [0u8; 32];
            recv_chain_key.copy_from_slice(&recv_chain_key_blob);

            let origin = str_to_origin(&origin_str);
            // РАНЬШЕ здесь звался Session::new(peer, origin, root_secret_placeholder),
            // который ВСЕГДА обнулял counter'ы/timestamps и пересобирал
            // ratchet с нуля из плейсхолдера — реальное состояние никогда
            // не переживало рестарт. Session::restore берёт реальное
            // RatchetState и реальные timestamps/счётчики напрямую.
            let session = Session::restore(
                peer,
                origin,
                RatchetState {
                    send_chain_key,
                    send_counter,
                    recv_chain_key,
                    recv_counter,
                },
                created_at as u64,
                last_used_at as u64,
                messages_sent as u64,
                messages_received as u64,
            );
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }
}

fn origin_to_str(o: SessionOrigin) -> &'static str {
    match o {
        SessionOrigin::Initiated => "initiated",
        SessionOrigin::Accepted => "accepted",
    }
}

fn str_to_origin(s: &str) -> SessionOrigin {
    match s {
        "accepted" => SessionOrigin::Accepted,
        _ => SessionOrigin::Initiated,
    }
}
