//! Временная замена DHT-каталога relay-узлов (см. комментарий у
//! `config::StaticRelay`). Отдаёт onion-ключи из захардкоженного в
//! конфиге списка вместо похода в DHT. Когда protocol/message.proto
//! научится описывать relay-дескрипторы — этот файл можно выкинуть и
//! заменить на настоящий `DhtOnionKeySource`, реализующий тот же трейт
//! `OnionKeySource`, ничего выше по стеку менять не придётся.

use std::collections::HashMap;

use crate::errors::{MessengerError, Result};
use crate::network::onion::RelayOnionKey;
use crate::network::relay::scoring::OnionKeySource;
use crate::network::RelayId;

pub struct StaticOnionKeySource {
    keys: HashMap<RelayId, RelayOnionKey>,
}

impl StaticOnionKeySource {
    /// Парсит hex-encoded X25519 ключи из конфига. Некорректные записи
    /// пропускаются с предупреждением в лог, а не паникой — плохо
    /// сконфигурированный один relay не должен ронять запуск ноды.
    pub fn from_config(relays: &[crate::config::StaticRelay]) -> Self {
        let mut keys = HashMap::new();
        for relay in relays {
            match hex::decode(&relay.onion_public_key_hex) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    keys.insert(relay.relay_id.clone(), RelayOnionKey::from(arr));
                }
                _ => {
                    tracing::warn!(
                        "Пропускаю static relay '{}': onion_public_key_hex невалиден (нужно 64 hex-символа)",
                        relay.relay_id
                    );
                }
            }
        }
        Self { keys }
    }
}

#[async_trait::async_trait]
impl OnionKeySource for StaticOnionKeySource {
    async fn fetch_onion_key(&self, relay: &RelayId) -> Result<RelayOnionKey> {
        self.keys
            .get(relay)
            .copied()
            .ok_or_else(|| MessengerError::OnionKeyNotFound(relay.clone()))
    }
}
