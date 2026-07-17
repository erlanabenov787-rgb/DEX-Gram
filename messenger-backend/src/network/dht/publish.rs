//! Публикация записей в Kademlia DHT и переопубликация до истечения TTL.
//! Вынесено из старого плоского dht.rs без изменения поведения публикации;
//! логика периодической переопубликации — новая, её раньше не было (был
//! только TTL как константа без кода, который бы его действительно
//! отслеживал).

use libp2p::kad;

use crate::protocol::{DhtRecord, PreKeyBundleRecord, RelayDescriptorRecord};

/// Реальная публикация записи в Kademlia DHT. Вызывается из p2p.rs,
/// когда нод стартует и хочет объявить о себе сети.
pub fn publish_record(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    record: &DhtRecord,
) -> anyhow::Result<kad::QueryId> {
    let key = super::record::record_key_for_user(&record.user_id);
    let value = prost::Message::encode_to_vec(record);

    let kad_record = kad::Record {
        key,
        value,
        publisher: None,
        expires: None, // TTL обрабатываем сами через expires_at_unix внутри DhtRecord
    };

    let query_id = kademlia
        .put_record(kad_record, kad::Quorum::One)
        .map_err(|e| anyhow::anyhow!("не удалось опубликовать DHT-запись: {e:?}"))?;

    Ok(query_id)
}

/// Публикация PreKeyBundleRecord — зеркалит publish_record выше, но под
/// отдельным DHT-ключом (см. record::prekey_bundle_key_for_user), чтобы
/// не конкурировать с DhtRecord за один Kademlia-слот.
pub fn publish_prekey_bundle(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    record: &PreKeyBundleRecord,
) -> anyhow::Result<kad::QueryId> {
    let key = super::record::prekey_bundle_key_for_user(&record.user_id);
    let value = prost::Message::encode_to_vec(record);

    let kad_record = kad::Record {
        key,
        value,
        publisher: None,
        expires: None,
    };

    let query_id = kademlia
        .put_record(kad_record, kad::Quorum::One)
        .map_err(|e| anyhow::anyhow!("не удалось опубликовать PreKeyBundle-запись: {e:?}"))?;

    Ok(query_id)
}

/// Публикация RelayDescriptorRecord — relay-узел вызывает это при старте
/// чтобы другие узлы могли найти его onion_public_key и строить через него
/// onion-маршруты. Ключ — Hash("relay:" + relay_id), отдельный домен от
/// пользовательских записей (см. record::relay_descriptor_key_for_relay).
pub fn publish_relay_descriptor(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    record: &RelayDescriptorRecord,
) -> anyhow::Result<kad::QueryId> {
    let key = super::record::relay_descriptor_key_for_relay(&record.relay_id);
    let value = prost::Message::encode_to_vec(record);

    let kad_record = kad::Record {
        key,
        value,
        publisher: None,
        expires: None,
    };

    let query_id = kademlia
        .put_record(kad_record, kad::Quorum::One)
        .map_err(|e| anyhow::anyhow!("не удалось опубликовать RelayDescriptor-запись: {e:?}"))?;

    Ok(query_id)
}

/// Решает, пора ли переопубликовывать запись — с запасом до истечения
/// TTL (DHT_REPUBLISH_INTERVAL_SECS), а не в последний момент: если
/// узел был оффлайн ровно в момент "последнего шанса", запись вымоется
/// из сети и её придётся поднимать заново через полный DHT_ANNOUNCE
/// цикл вместо простого refresh.
pub fn needs_republish(record: &DhtRecord) -> bool {
    let now = super::record::now_unix();
    let republish_deadline = record
        .expires_at_unix
        .saturating_sub(crate::constants::DHT_REPUBLISH_INTERVAL_SECS);
    now >= republish_deadline
}

/// Вызывается периодически из services/background.rs (когда появится):
/// проверяет нашу собственную запись и переопубликовывает если пора.
/// `current_record` + `rebuild_fn` разделены специально: rebuild_fn
/// пересобирает свежий DhtRecord (новый TTL, возможно новые
/// mailbox_candidates если relay-набор поменялся) — republish тут не
/// просто "отправь то же самое ещё раз", а "пересобери актуальное
/// состояние и отправь".
pub fn republish_if_needed(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    current_record: &DhtRecord,
    rebuild_fn: impl FnOnce() -> DhtRecord,
) -> anyhow::Result<Option<kad::QueryId>> {
    if !needs_republish(current_record) {
        return Ok(None);
    }
    let fresh_record = rebuild_fn();
    let query_id = publish_record(kademlia, &fresh_record)?;
    Ok(Some(query_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(expires_in_secs: u64) -> DhtRecord {
        DhtRecord {
            user_id: "alice".to_string(),
            public_key: vec![1, 2, 3],
            mailbox_candidates: vec![],
            expires_at_unix: super::super::record::now_unix() + expires_in_secs,
            signature: vec![],
            pow_nonce: vec![],
        }
    }

    #[test]
    fn does_not_need_republish_when_far_from_expiry() {
        let record = sample_record(crate::constants::DHT_RECORD_TTL_SECS);
        assert!(!needs_republish(&record));
    }

    #[test]
    fn needs_republish_when_close_to_expiry() {
        // Осталось меньше, чем DHT_REPUBLISH_INTERVAL_SECS до истечения
        let record = sample_record(60);
        assert!(needs_republish(&record));
    }
}
