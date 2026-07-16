//! Конфигурация нода. На Android путь к базе будет отличаться от
//! десктопа — это то место, где меняется под платформу.

use serde::{Deserialize, Serialize};

/// Relay-узел, полученный от bootstrap при подключении.
///
/// Больше не хранится в конфигурации клиента вручную — источник истины
/// только bootstrap. Используется как промежуточная структура при
/// получении списка relay от bootstrap и при передаче его в RelayRegistry
/// через NodeCommand::UpdateRelays.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayInfo {
    /// libp2p PeerId этого узла (строкой).
    pub relay_id: String,
    /// Multiaddr, по которому его набирать.
    pub address: String,
    /// X25519 onion-публичный ключ узла, в hex (64 символа = 32 байта).
    pub onion_public_key_hex: String,
}

/// Совместимость: прежнее имя StaticRelay переименовано в RelayInfo.
/// Код, использующий StaticRelay, должен перейти на RelayInfo.
pub type StaticRelay = RelayInfo;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub listen_port: u16,
    pub db_path: String,
    /// Bootstrap-ноды для первоначального подключения к сети.
    /// После соединения с bootstrap клиент автоматически получает
    /// список relay — пользователь relay не вводит вручную.
    pub bootstrap_nodes: Vec<String>,
    pub is_relay: bool,
    pub relay_max_bandwidth_kbps: u32,
    pub pow_difficulty_bits: u32,
    pub dummy_traffic_interval_secs_min: u64,
    pub dummy_traffic_interval_secs_max: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 0,
            db_path: "./messenger.db".to_string(),
            bootstrap_nodes: vec![
                "/ip4/127.0.0.1/tcp/4001".to_string(),
            ],
            is_relay: false,
            relay_max_bandwidth_kbps: 1000,
            pow_difficulty_bits: 20,
            dummy_traffic_interval_secs_min: 20,
            dummy_traffic_interval_secs_max: 40,
        }
    }
}

impl Config {
    pub fn with_android_paths(mut self, app_files_dir: &str) -> Self {
        self.db_path = format!("{app_files_dir}/messenger.db");
        self
    }

    /// Собирает конфиг из переменных окружения, поверх Config::default().
    ///
    /// Пользователь задаёт только bootstrap — relay приходят автоматически.
    ///
    /// Переменные:
    /// - LISTEN_PORT (u16)
    /// - DB_PATH (строка)
    /// - BOOTSTRAP_NODES (multiaddr через запятую)
    /// - IS_RELAY ("true"/"1"/"false"/"0")
    /// - RELAY_MAX_BANDWIDTH_KBPS (u32)
    /// - POW_DIFFICULTY_BITS (u32)
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        if let Ok(v) = std::env::var("LISTEN_PORT") {
            match v.parse() {
                Ok(port) => cfg.listen_port = port,
                Err(e) => tracing::warn!("LISTEN_PORT='{v}' не распарсился как u16: {e}, использую значение по умолчанию"),
            }
        }

        if let Ok(v) = std::env::var("DB_PATH") {
            cfg.db_path = v;
        }

        if let Ok(v) = std::env::var("BOOTSTRAP_NODES") {
            cfg.bootstrap_nodes = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }

        if let Ok(v) = std::env::var("IS_RELAY") {
            match v.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => cfg.is_relay = true,
                "false" | "0" => cfg.is_relay = false,
                other => tracing::warn!("IS_RELAY='{other}' не распознан (ожидался true/false/1/0), использую значение по умолчанию"),
            }
        }

        if let Ok(v) = std::env::var("RELAY_MAX_BANDWIDTH_KBPS") {
            match v.parse() {
                Ok(n) => cfg.relay_max_bandwidth_kbps = n,
                Err(e) => tracing::warn!("RELAY_MAX_BANDWIDTH_KBPS='{v}' не распарсился: {e}"),
            }
        }

        if let Ok(v) = std::env::var("POW_DIFFICULTY_BITS") {
            match v.parse() {
                Ok(n) => cfg.pow_difficulty_bits = n,
                Err(e) => tracing::warn!("POW_DIFFICULTY_BITS='{v}' не распарсился: {e}"),
            }
        }

        cfg
    }
}
