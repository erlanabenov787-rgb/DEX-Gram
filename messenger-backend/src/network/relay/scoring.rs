//! Выбор relay-узлов для onion-цепочки (network/onion/builder.rs).
//!
//! Репутация по очкам (`known_relays.reputation_score`) уже считает
//! `storage/db.rs` и `RouteBuilder::pick_route` в relay.rs — этот файл
//! добавляет то, чего там нет: исключение узлов по количеству
//! ПОДРЯД ИДУЩИХ отказов (не путать с общим reputation_score, который
//! копится за всё время и медленно "прощает" старые провалы). Долгий
//! накопленный score не защищает от узла, который отвалился ПРЯМО
//! СЕЙЧАС (например, ушёл в оффлайн) — для этого нужен отдельный
//! счётчик, который сбрасывается при первом же успехе.
//!
//! Также этот файл отвечает за перевод "просто relay_id с репутацией"
//! в `OnionHop` с реальным onion-ключом (X25519), который нужен
//! network/onion/builder.rs — тот ключ живёт в DHT-записи relay-узла,
//! не в known_relays (там только TCP/QUIC-адрес для соединения).

use std::collections::HashMap;
use std::sync::RwLock;

use crate::constants::{ONION_MAX_HOPS, ONION_MIN_HOPS, RELAY_FAILURE_THRESHOLD};
use crate::errors::{MessengerError, Result};
use crate::network::onion::{OnionHop, RelayOnionKey};
use crate::network::RelayId;
use crate::storage::Database;

/// То, что нужно чтобы построить `OnionHop` — приходит из DHT lookup
/// (network/dht/lookup.rs), а не из локальной SQLite-репутации.
#[async_trait::async_trait]
pub trait OnionKeySource: Send + Sync {
    async fn fetch_onion_key(&self, relay: &RelayId) -> Result<RelayOnionKey>;
}

/// Счётчики подряд идущих отказов — в памяти, не персистится: если
/// процесс перезапустился, узлам даём чистый лист (иначе временная сеть
/// проблема при рестарте могла бы навсегда забанить рабочий relay).
pub struct RelayScoring {
    consecutive_failures: RwLock<HashMap<RelayId, u32>>,
    db: std::sync::Arc<Database>,
    onion_keys: std::sync::Arc<dyn OnionKeySource>,
}

impl RelayScoring {
    pub fn new(db: std::sync::Arc<Database>, onion_keys: std::sync::Arc<dyn OnionKeySource>) -> Self {
        Self {
            consecutive_failures: RwLock::new(HashMap::new()),
            db,
            onion_keys,
        }
    }

    /// Вызывается когда relay успешно переслал пакет (например,
    /// подтверждено получением ack от следующего хопа).
    pub fn record_success(&self, relay: &RelayId) {
        let mut failures = self.consecutive_failures.write().unwrap();
        failures.remove(relay);
        // Долгосрочный score в SQLite копится отдельно и медленнее —
        // см. Database::upsert_relay_reputation, здесь только сбрасываем
        // счётчик подряд идущих отказов.
        let _ = self.db.upsert_relay_reputation(relay, "", 1.0);
    }

    /// Вызывается когда relay не ответил / отклонил пакет / соединение
    /// оборвалось на нём.
    pub fn record_failure(&self, relay: &RelayId) {
        let mut failures = self.consecutive_failures.write().unwrap();
        *failures.entry(relay.clone()).or_insert(0) += 1;
        let _ = self.db.upsert_relay_reputation(relay, "", -1.0);
    }

    fn is_excluded(&self, relay: &RelayId) -> bool {
        let failures = self.consecutive_failures.read().unwrap();
        failures
            .get(relay)
            .map(|&count| count >= RELAY_FAILURE_THRESHOLD)
            .unwrap_or(false)
    }

    /// Выбирает `hop_count` узлов, готовых к использованию в
    /// build_circuit: с известным onion-ключом и без свежих отказов.
    /// hop_count по умолчанию берём из ONION_MIN_HOPS если не указан
    /// вызывающим кодом.
    pub async fn select_hops(&self, hop_count: usize) -> Result<Vec<OnionHop>> {
        let hop_count = hop_count.clamp(ONION_MIN_HOPS, ONION_MAX_HOPS);

        // Берём с запасом (x4), т.к. часть кандидатов отсеется из-за
        // is_excluded или отсутствия onion-ключа в DHT.
        let candidates = self
            .db
            .best_relays((hop_count * 4) as u32)
            .map_err(MessengerError::Storage)?;

        let mut hops = Vec::with_capacity(hop_count);
        for (relay_id, _address, _score) in candidates {
            if hops.len() == hop_count {
                break;
            }
            if self.is_excluded(&relay_id) {
                continue;
            }
            match self.onion_keys.fetch_onion_key(&relay_id).await {
                Ok(onion_key) => hops.push(OnionHop { relay_id, onion_key }),
                // Relay в известной таблице, но его DHT-запись не найдена
                // или устарела — пропускаем, не считаем это record_failure
                // (это не отказ пересылки, а проблема публикации ключа).
                Err(_) => continue,
            }
        }

        if hops.len() < hop_count {
            return Err(MessengerError::OnionChainTooShort {
                min: hop_count,
                got: hops.len(),
            });
        }

        Ok(hops)
    }

    /// Выбирает конкретный exit-хоп из списка `candidates` — используется
    /// вместо оставшегося места в select_hops, когда получатель уже
    /// известен: раньше exit-узел выбирался ИЗ СВОИХ ЖЕ known relays
    /// (select_hops выше), без всякой связи с тем, что получатель
    /// реально опубликовал в своём DhtRecord::mailbox_candidates. Из-за
    /// этого сообщение могло осесть на relay, который получатель никогда
    /// не станет опрашивать (см. dispatcher::fetch_mailbox) — то есть
    /// формально "доставлено", а реально не читаемо НИКОГДА.
    ///
    /// Пробует кандидатов по порядку (в том порядке, в каком их
    /// опубликовал получатель), пропуская тех, кто в бан-листе
    /// (is_excluded) или чей onion-ключ не резолвится через
    /// OnionKeySource (см. те же две причины пропуска, что и в
    /// select_hops). Возвращает первый, который прошёл обе проверки.
    pub async fn select_exit_from(&self, candidates: &[RelayId]) -> Result<OnionHop> {
        if candidates.is_empty() {
            return Err(MessengerError::OnionChainTooShort { min: 1, got: 0 });
        }
        for relay_id in candidates {
            if self.is_excluded(relay_id) {
                continue;
            }
            match self.onion_keys.fetch_onion_key(relay_id).await {
                Ok(onion_key) => {
                    return Ok(OnionHop {
                        relay_id: relay_id.clone(),
                        onion_key,
                    })
                }
                Err(_) => continue,
            }
        }
        Err(MessengerError::OnionChainTooShort {
            min: 1,
            got: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeKeySource;

    #[async_trait::async_trait]
    impl OnionKeySource for FakeKeySource {
        async fn fetch_onion_key(&self, _relay: &RelayId) -> Result<RelayOnionKey> {
            let sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
            Ok(x25519_dalek::PublicKey::from(&sk))
        }
    }

    #[test]
    fn failure_threshold_excludes_relay() {
        let db = std::sync::Arc::new(Database::open_in_memory().unwrap());
        let scoring = RelayScoring::new(db, std::sync::Arc::new(FakeKeySource));

        let relay = "relay_flaky".to_string();
        for _ in 0..RELAY_FAILURE_THRESHOLD {
            scoring.record_failure(&relay);
        }
        assert!(scoring.is_excluded(&relay));

        scoring.record_success(&relay);
        assert!(!scoring.is_excluded(&relay));
    }
}
