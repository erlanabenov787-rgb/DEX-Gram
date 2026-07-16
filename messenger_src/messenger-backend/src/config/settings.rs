//! Конфигурация нода. На Android путь к базе будет отличаться от
//! десктопа — это то место, где меняется под платформу.

use serde::{Deserialize, Serialize};

/// Один relay-узел, о котором мы знаем заранее (не через DHT).
///
/// ЧЕСТНО: полноценный DHT-каталог relay-узлов (публикация их
/// onion-ключей через сеть) ещё не реализован — protocol/message.proto
/// сейчас умеет описывать только пользователей (`DhtRecord`), не
/// relay-узлы. Пока используем этот фиксированный список из конфига,
/// чтобы onion routing реально работал end-to-end. Нужно минимум 3
/// таких записи (ONION_MIN_HOPS) — иначе выбор цепочки будет падать
/// с "недостаточно known relays".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaticRelay {
    /// Совпадает с libp2p PeerId этого узла (строкой).
    pub relay_id: String,
    /// Multiaddr, по которому его набирать при старте.
    pub address: String,
    /// X25519 onion-публичный ключ узла, в hex (64 символа = 32 байта).
    pub onion_public_key_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub listen_port: u16,
    pub db_path: String,
    pub bootstrap_nodes: Vec<String>,
    pub is_relay: bool,
    pub relay_max_bandwidth_kbps: u32,
    pub pow_difficulty_bits: u32,
    pub dummy_traffic_interval_secs_min: u64,
    pub dummy_traffic_interval_secs_max: u64,
    /// См. StaticRelay — временная замена DHT-каталога relay-узлов.
    pub static_relays: Vec<StaticRelay>,
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
            // Пусто по умолчанию — приложение обязано заполнить это
            // хотя бы 3 записями (см. StaticRelay) прежде чем отправка
            // сообщений через onion сможет что-то реально построить.
            static_relays: Vec::new(),
        }
    }
}

impl Config {
    pub fn with_android_paths(mut self, app_files_dir: &str) -> Self {
        self.db_path = format!("{app_files_dir}/messenger.db");
        self
    }

    /// Собирает конфиг из переменных окружения, поверх Config::default() —
    /// без этого единственным способом задать static_relays/is_relay/etc
    /// было перекомпилировать бинарник с другим Default::default().
    /// Любая переменная, которой нет в окружении, просто оставляет
    /// значение по умолчанию как есть.
    ///
    /// Переменные:
    /// - LISTEN_PORT (u16)
    /// - DB_PATH (строка)
    /// - BOOTSTRAP_NODES (multiaddr через запятую)
    /// - IS_RELAY ("true"/"1"/"false"/"0")
    /// - RELAY_MAX_BANDWIDTH_KBPS (u32)
    /// - POW_DIFFICULTY_BITS (u32)
    /// - STATIC_RELAYS (JSON-массив StaticRelay, например
    ///   `[{"relay_id":"12D3Koo...","address":"/ip4/1.2.3.4/tcp/4001","onion_public_key_hex":"ab..cd"}]`)
    ///
    /// Ошибки парсинга не паникуют — логируется warning и используется
    /// значение по умолчанию, чтобы опечатка в одной переменной не
    /// уронила старт нода целиком.
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

        if let Ok(v) = std::env::var("STATIC_RELAYS") {
            match serde_json::from_str::<Vec<StaticRelay>>(&v) {
                Ok(relays) => cfg.static_relays = relays,
                Err(e) => tracing::warn!("STATIC_RELAYS не распарсился как JSON-массив: {e}, использую значение по умолчанию (пусто)"),
            }
        }

        cfg
    }
}