//! Динамический реестр relay-узлов.
//!
//! Заменяет прежний StaticOnionKeySource (жёстко прописанные relay
//! из конфига). RelayRegistry живёт в runtime и заполняется bootstrap-ом
//! при первом подключении через NodeCommand::UpdateRelays.
//!
//! Если bootstrap позже вернёт обновлённый список — клиент заменяет
//! старый список новым без перезапуска (update() атомарно меняет всё).
//!
//! Для слоёв выше (scoring, dispatcher) это просто Arc<dyn OnionKeySource> —
//! никакого API изменения не требуется.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::errors::{MessengerError, Result};
use crate::network::onion::RelayOnionKey;
use crate::network::relay::scoring::OnionKeySource;
use crate::network::RelayId;

/// Информация об одном relay-узле, полученная от bootstrap.
#[derive(Clone, Debug)]
pub struct RelayEntry {
    /// libp2p PeerId (строка) — идентификатор узла в сети.
    pub relay_id: String,
    /// Multiaddr для подключения.
    pub address: String,
    /// X25519 onion-публичный ключ, 32 байта.
    pub onion_public_key: RelayOnionKey,
}

impl RelayEntry {
    /// Создаёт RelayEntry из hex-кодированного onion-ключа.
    /// Возвращает None если ключ невалиден (не 64 hex-символа / не 32 байта).
    pub fn from_hex_key(relay_id: String, address: String, onion_public_key_hex: &str) -> Option<Self> {
        let bytes = hex::decode(onion_public_key_hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(Self {
            relay_id,
            address,
            onion_public_key: x25519_dalek::PublicKey::from(arr),
        })
    }
}

/// Динамический реестр relay-узлов.
///
/// Используется как `Arc<RelayRegistry>` — дёшево клонируется и шарится
/// между задачами. Внутренний RwLock позволяет читать параллельно, а
/// update() держит write lock только на момент замены списка.
///
/// После получения relay-списка от bootstrap вызвать update() —
/// все задачи (background, scoring) автоматически увидят новый список
/// при следующем обращении.
pub struct RelayRegistry {
    inner: RwLock<HashMap<RelayId, RelayEntry>>,
}

impl RelayRegistry {
    /// Создаёт пустой реестр. Заполняется позже через update().
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(HashMap::new()),
        })
    }

    /// Заменяет весь список relay на новый (от bootstrap).
    ///
    /// Предыдущие записи удаляются — источник истины всегда bootstrap.
    /// Если bootstrap позже вернёт обновлённый список, просто вызвать
    /// update() снова.
    pub fn update(&self, relays: Vec<RelayEntry>) {
        let mut map = self.inner.write().unwrap();
        map.clear();
        for entry in relays {
            map.insert(entry.relay_id.clone(), entry);
        }
        tracing::info!("RelayRegistry обновлён: {} relay(s)", map.len());
    }

    /// Текущий список relay_id — используется background задачами
    /// для mailbox fetch / dummy traffic. Читается на каждой итерации,
    /// поэтому автоматически отражает обновления от bootstrap.
    pub fn relay_ids(&self) -> Vec<RelayId> {
        self.inner.read().unwrap().keys().cloned().collect()
    }

    /// Текущий список всех записей — используется NodeHandle для
    /// подключения к новым relay при обработке UpdateRelays.
    pub fn all_entries(&self) -> Vec<RelayEntry> {
        self.inner.read().unwrap().values().cloned().collect()
    }

    /// Возвращает true если реестр пуст (bootstrap ещё не ответил).
    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    /// Парсит список relay из config-совместимых структур (relay_id,
    /// address, onion_public_key_hex). Используется для обратной
    /// совместимости и для приёма данных от bootstrap.
    /// Некорректные записи пропускаются с предупреждением.
    pub fn entries_from_hex(
        relays: &[(String, String, String)],
    ) -> Vec<RelayEntry> {
        relays
            .iter()
            .filter_map(|(relay_id, address, hex_key)| {
                match RelayEntry::from_hex_key(relay_id.clone(), address.clone(), hex_key) {
                    Some(entry) => Some(entry),
                    None => {
                        tracing::warn!(
                            "Пропускаю relay '{}': onion_public_key_hex невалиден (нужно 64 hex-символа)",
                            relay_id
                        );
                        None
                    }
                }
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl OnionKeySource for RelayRegistry {
    async fn fetch_onion_key(&self, relay: &RelayId) -> Result<RelayOnionKey> {
        self.inner
            .read()
            .unwrap()
            .get(relay)
            .map(|e| e.onion_public_key)
            .ok_or_else(|| MessengerError::OnionKeyNotFound(relay.clone()))
    }
}
