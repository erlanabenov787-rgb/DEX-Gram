//! Сборка, подпись и проверка DhtRecord / PreKeyBundleRecord / RelayDescriptorRecord.
//! Вынесено из старого плоского dht.rs без изменения поведения — это
//! чистый рефакторинг, логика та же самая.
//!
//! Важное замечание о signed_prekey_signature семантике:
//! signed_prekey_signature покрывает ТОЛЬКО байты signed_prekey-ключа
//! (Signal-семантика "подпись публичного ключа обмена"). Это позволяет
//! session/manager.rs::verify_bundle_signature проверить подпись имея
//! только PreKeyBundle — без expires_at_unix, user_id и прочих полей
//! исходной записи, которых у него нет. PoW по-прежнему считается
//! поверх полного содержимого записи (prekey_signable_bytes) — анти-спам
//! мера должна покрывать весь объём, не только ключ.

use crate::crypto::pow::PowChallenge;
use crate::identity::UserId;
use crate::network::RelayId;
use crate::protocol::{DhtRecord, PreKeyBundleRecord, RelayDescriptorRecord};
use libp2p::kad::RecordKey;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn record_key_for_user(user_id: &UserId) -> RecordKey {
    let hash = Sha256::digest(user_id.as_bytes());
    RecordKey::new(&hash.to_vec())
}

/// Отдельный DHT-ключ под PreKeyBundleRecord — намеренно НЕ тот же ключ,
/// что `record_key_for_user`, чтобы DhtRecord (мелкая, часто читаемая
/// запись) и PreKeyBundleRecord (крупнее — несёт до PREKEY_BATCH_SIZE
/// one-time prekeys) не конкурировали за один Kademlia-слот и не путались
/// при публикации/переопубликации с разными TTL-циклами.
pub fn prekey_bundle_key_for_user(user_id: &UserId) -> RecordKey {
    let hash = Sha256::digest(format!("prekey:{user_id}").as_bytes());
    RecordKey::new(&hash.to_vec())
}

/// DHT-ключ для relay-дескриптора — отдельный домен, чтобы не путать с
/// пользовательскими записями DhtRecord/PreKeyBundleRecord.
pub fn relay_descriptor_key_for_relay(relay_id: &RelayId) -> RecordKey {
    let hash = Sha256::digest(format!("relay:{relay_id}").as_bytes());
    RecordKey::new(&hash.to_vec())
}

/// Один новый X25519 статический ключ — используется и для signed
/// prekey, и (при первом запуске) для x3dh identity-ключа: с
/// криптографической точки зрения это один и тот же тип ключа, разница
/// только в том, как долго он живёт и как используется вызывающим кодом.
pub fn generate_signed_prekey() -> StaticSecret {
    StaticSecret::random_from_rng(rand_core::OsRng)
}

/// Пул одноразовых X25519 ключей для forward secrecy первого сообщения
/// (DH4 в X3DH). Каждый расходуется максимум один раз — см. честную
/// пометку про race condition в DhtLookupSource::fetch_bundle.
pub fn generate_one_time_prekeys(count: usize) -> Vec<StaticSecret> {
    (0..count)
        .map(|_| StaticSecret::random_from_rng(rand_core::OsRng))
        .collect()
}

/// Собирает DhtRecord перед публикацией. TTL по умолчанию 24 часа —
/// после истечения запись надо переопубликовать (с новым mini-PoW),
/// это и есть анти-Sybil мера против "накидать миллион фейковых
/// записей и забыть" — поддерживать их вечно дорого.
pub struct DhtRecordBuilder;

impl DhtRecordBuilder {
    pub const DEFAULT_TTL_SECS: u64 = crate::constants::DHT_RECORD_TTL_SECS;

    pub fn build(
        user_id: &UserId,
        public_key: Vec<u8>,
        mailbox_candidates: Vec<String>,
        sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> DhtRecord {
        let expires_at = now_unix() + Self::DEFAULT_TTL_SECS;

        let mut record = DhtRecord {
            user_id: user_id.clone(),
            public_key,
            mailbox_candidates,
            expires_at_unix: expires_at,
            signature: vec![],
            pow_nonce: vec![],
        };

        // Подписываем всё кроме самой подписи
        let to_sign = signable_bytes(&record);
        record.signature = sign_fn(&to_sign);

        // PoW против DHT-флуда фейковыми записями. Challenge выводится
        // детерминированно из подписанных байт (a) чтобы верификатор
        // мог пересчитать тот же challenge и реально проверить nonce
        // (см. verify() ниже), и (b) чтобы challenge был привязан к
        // конкретной записи — нельзя решить PoW один раз и переиспользовать
        // nonce для другой записи/подписи.
        let challenge = PowChallenge::derive_from(
            "dht_record",
            &to_sign,
            crate::crypto::pow::DEFAULT_DIFFICULTY_BITS,
        );
        let solution = challenge.solve();
        record.pow_nonce = solution.nonce.to_le_bytes().to_vec();

        record
    }

    /// Проверка перед тем как принять чужую запись из сети:
    /// подпись + не протухла + PoW решён.
    pub fn verify(
        record: &DhtRecord,
        verify_fn: impl FnOnce(&[u8], &[u8]) -> bool,
    ) -> anyhow::Result<()> {
        if record.expires_at_unix < now_unix() {
            anyhow::bail!("DHT record expired");
        }

        let to_sign = signable_bytes(record);
        if !verify_fn(&to_sign, &record.signature) {
            anyhow::bail!("invalid signature on DHT record");
        }

        let challenge = PowChallenge::derive_from(
            "dht_record",
            &to_sign,
            crate::crypto::pow::DEFAULT_DIFFICULTY_BITS,
        );
        let nonce_bytes: [u8; 8] = record
            .pow_nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed pow_nonce on DHT record"))?;
        let solution = crate::crypto::pow::PowSolution {
            nonce: u64::from_le_bytes(nonce_bytes),
        };
        if !challenge.verify(&solution) {
            anyhow::bail!("PoW verification failed on DHT record");
        }

        Ok(())
    }
}

/// Сборка, подпись и проверка PreKeyBundleRecord.
///
/// СЕМАНТИКА signed_prekey_signature: подпись покрывает ТОЛЬКО
/// `signed_prekey.as_bytes()` (Signal-семантика: "я удостоверяю этот
/// X25519-ключ обмена своим ed25519 identity-ключом"). Это позволяет
/// session/manager.rs::verify_bundle_signature проверить подпись имея
/// только структуру PreKeyBundle — без expires_at_unix, user_id и
/// прочих полей, которых в PreKeyBundle нет. PoW по-прежнему считается
/// поверх prekey_signable_bytes (полный контент) — анти-спам мера
/// должна покрывать весь объём записи.
///
/// Важное отличие от DhtRecordBuilder: подписывается НЕ x3dh-ключом
/// (иначе получилась бы циркулярная зависимость — X3DH ключ подписывает
/// сам себя), а ed25519 identity-ключом пользователя — тем же, что
/// подписывает DhtRecord и исходящие сообщения (см. identity/mod.rs).
pub struct PreKeyBundleRecordBuilder;

impl PreKeyBundleRecordBuilder {
    pub const DEFAULT_TTL_SECS: u64 = crate::constants::DHT_RECORD_TTL_SECS;

    pub fn build(
        user_id: &UserId,
        x3dh_identity_public: &PublicKey,
        signed_prekey_public: &PublicKey,
        one_time_prekey_publics: &[PublicKey],
        sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> PreKeyBundleRecord {
        let expires_at = now_unix() + Self::DEFAULT_TTL_SECS;

        let mut record = PreKeyBundleRecord {
            user_id: user_id.clone(),
            x3dh_identity_key: x3dh_identity_public.as_bytes().to_vec(),
            signed_prekey: signed_prekey_public.as_bytes().to_vec(),
            signed_prekey_signature: vec![],
            one_time_prekeys: one_time_prekey_publics
                .iter()
                .map(|k| k.as_bytes().to_vec())
                .collect(),
            expires_at_unix: expires_at,
            pow_nonce: vec![],
        };

        // Подписываем ТОЛЬКО signed_prekey-ключ (Signal-семантика):
        // верификатор в session/manager.rs знает только байты ключа и
        // ed25519 verifying key собеседника — у него нет expires_at_unix,
        // user_id и т.д. из исходной записи. Это позволяет проверить
        // подпись с одним лишь PreKeyBundle (без оригинального Record).
        record.signed_prekey_signature = sign_fn(signed_prekey_public.as_bytes());

        // PoW поверх полного содержимого (включая только что поставленную
        // подпись) — анти-спам мера должна покрывать весь объём.
        let to_sign = prekey_signable_bytes(&record);
        let challenge = PowChallenge::derive_from(
            "prekey_bundle",
            &to_sign,
            crate::crypto::pow::DEFAULT_DIFFICULTY_BITS,
        );
        let solution = challenge.solve();
        record.pow_nonce = solution.nonce.to_le_bytes().to_vec();

        record
    }

    /// Проверка перед тем как принять чужой бандл из сети: подпись +
    /// не протух + PoW решён. verify_fn должен быть построен вызывающим
    /// кодом на основе ed25519 verifying key владельца UserID.
    ///
    /// verify_fn получает (signed_prekey_bytes, signature) — подпись
    /// покрывает только signed_prekey (Signal-семантика).
    pub fn verify(
        record: &PreKeyBundleRecord,
        verify_fn: impl FnOnce(&[u8], &[u8]) -> bool,
    ) -> anyhow::Result<()> {
        if record.expires_at_unix < now_unix() {
            anyhow::bail!("prekey bundle record expired");
        }

        // Подпись покрывает только signed_prekey (Signal-семантика).
        // verify_fn получает сами байты ключа как сообщение.
        if !verify_fn(record.signed_prekey.as_slice(), &record.signed_prekey_signature) {
            anyhow::bail!("invalid signature on prekey bundle record");
        }

        // PoW challenge — из полного содержимого записи (анти-спам).
        let to_sign = prekey_signable_bytes(record);
        let challenge = PowChallenge::derive_from(
            "prekey_bundle",
            &to_sign,
            crate::crypto::pow::DEFAULT_DIFFICULTY_BITS,
        );
        let nonce_bytes: [u8; 8] = record
            .pow_nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed pow_nonce on prekey bundle record"))?;
        let solution = crate::crypto::pow::PowSolution {
            nonce: u64::from_le_bytes(nonce_bytes),
        };
        if !challenge.verify(&solution) {
            anyhow::bail!("PoW verification failed on prekey bundle record");
        }

        Ok(())
    }
}

/// Сборка, подпись и проверка RelayDescriptorRecord.
///
/// Relay публикует этот дескриптор в DHT под ключом
/// `relay_descriptor_key_for_relay(relay_id)`, чтобы другие узлы могли
/// строить через него onion-маршруты. Семантика подписи та же, что у
/// PreKeyBundleRecord: signature покрывает только сам onion_public_key
/// (минимальные данные, которые нужны верификатору при построении цепочки).
pub struct RelayDescriptorRecordBuilder;

impl RelayDescriptorRecordBuilder {
    pub const DEFAULT_TTL_SECS: u64 = crate::constants::DHT_RECORD_TTL_SECS;

    /// `sign_fn` — ed25519-подпись relay'я (например из его Identity).
    pub fn build(
        relay_id: &RelayId,
        onion_public_key: &PublicKey,
        sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> RelayDescriptorRecord {
        let expires_at = now_unix() + Self::DEFAULT_TTL_SECS;

        let mut record = RelayDescriptorRecord {
            relay_id: relay_id.clone(),
            onion_public_key: onion_public_key.as_bytes().to_vec(),
            expires_at_unix: expires_at,
            signature: vec![],
            pow_nonce: vec![],
        };

        // Подпись поверх onion_public_key (Signal-семантика: подписываем
        // только сам ключ, а не весь контент записи).
        record.signature = sign_fn(onion_public_key.as_bytes());

        // PoW поверх полного содержимого (анти-спам).
        let to_sign = relay_signable_bytes(&record);
        let challenge = PowChallenge::derive_from(
            "relay_descriptor",
            &to_sign,
            crate::crypto::pow::DEFAULT_DIFFICULTY_BITS,
        );
        let solution = challenge.solve();
        record.pow_nonce = solution.nonce.to_le_bytes().to_vec();

        record
    }

    pub fn verify(
        record: &RelayDescriptorRecord,
        verify_fn: impl FnOnce(&[u8], &[u8]) -> bool,
    ) -> anyhow::Result<()> {
        if record.expires_at_unix < now_unix() {
            anyhow::bail!("relay descriptor record expired");
        }

        // Подпись покрывает только onion_public_key (Signal-семантика).
        if !verify_fn(record.onion_public_key.as_slice(), &record.signature) {
            anyhow::bail!("invalid signature on relay descriptor record");
        }

        // PoW поверх полного содержимого.
        let to_sign = relay_signable_bytes(record);
        let challenge = PowChallenge::derive_from(
            "relay_descriptor",
            &to_sign,
            crate::crypto::pow::DEFAULT_DIFFICULTY_BITS,
        );
        let nonce_bytes: [u8; 8] = record
            .pow_nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed pow_nonce on relay descriptor record"))?;
        let solution = crate::crypto::pow::PowSolution {
            nonce: u64::from_le_bytes(nonce_bytes),
        };
        if !challenge.verify(&solution) {
            anyhow::bail!("PoW verification failed on relay descriptor record");
        }

        Ok(())
    }
}

fn prekey_signable_bytes(record: &PreKeyBundleRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(record.user_id.as_bytes());
    buf.extend_from_slice(&record.x3dh_identity_key);
    buf.extend_from_slice(&record.signed_prekey);
    buf.extend_from_slice(&record.signed_prekey_signature);
    for otpk in &record.one_time_prekeys {
        buf.extend_from_slice(otpk);
    }
    buf.extend_from_slice(&record.expires_at_unix.to_le_bytes());
    buf
}

fn signable_bytes(record: &DhtRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(record.user_id.as_bytes());
    buf.extend_from_slice(&record.public_key);
    for candidate in &record.mailbox_candidates {
        buf.extend_from_slice(candidate.as_bytes());
    }
    buf.extend_from_slice(&record.expires_at_unix.to_le_bytes());
    buf
}

fn relay_signable_bytes(record: &RelayDescriptorRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(record.relay_id.as_bytes());
    buf.extend_from_slice(&record.onion_public_key);
    buf.extend_from_slice(&record.signature);
    buf.extend_from_slice(&record.expires_at_unix.to_le_bytes());
    buf
}

pub(super) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_key_is_deterministic() {
        let k1 = record_key_for_user(&"user123".to_string());
        let k2 = record_key_for_user(&"user123".to_string());
        assert_eq!(k1, k2);
    }

    #[test]
    fn prekey_bundle_key_differs_from_record_key() {
        let user = "user123".to_string();
        assert_ne!(record_key_for_user(&user), prekey_bundle_key_for_user(&user));
    }

    #[test]
    fn relay_descriptor_key_differs_from_record_key() {
        let relay = "12D3KooWRelay".to_string();
        // relay DHT key ≠ user DHT key ≠ prekey DHT key
        assert_ne!(
            relay_descriptor_key_for_relay(&relay),
            record_key_for_user(&relay)
        );
        assert_ne!(
            relay_descriptor_key_for_relay(&relay),
            prekey_bundle_key_for_user(&relay)
        );
    }

    #[test]
    fn relay_descriptor_key_is_deterministic() {
        let relay = "12D3KooWRelay".to_string();
        assert_eq!(
            relay_descriptor_key_for_relay(&relay),
            relay_descriptor_key_for_relay(&relay)
        );
    }

    #[test]
    fn prekey_bundle_build_and_verify_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let x3dh_identity = generate_signed_prekey();
        let signed_prekey = generate_signed_prekey();
        let otpks = generate_one_time_prekeys(3);
        let otpk_publics: Vec<PublicKey> = otpks.iter().map(PublicKey::from).collect();

        let record = PreKeyBundleRecordBuilder::build(
            &"alice".to_string(),
            &PublicKey::from(&x3dh_identity),
            &PublicKey::from(&signed_prekey),
            &otpk_publics,
            // sign_fn получает только signed_prekey-байты (Signal-семантика)
            |bytes| signing_key.sign(bytes).to_bytes().to_vec(),
        );

        // verify_fn тоже получает signed_prekey-байты как сообщение
        let result = PreKeyBundleRecordBuilder::verify(&record, |msg, sig| {
            let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
                return false;
            };
            verifying_key
                .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                .is_ok()
        });
        assert!(result.is_ok());
    }

    #[test]
    fn relay_descriptor_build_and_verify_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

        let signing_key = SigningKey::generate(&mut rand_core::OsRng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        let onion_sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let onion_pk = PublicKey::from(&onion_sk);

        let record = RelayDescriptorRecordBuilder::build(
            &"12D3KooWRelay".to_string(),
            &onion_pk,
            |bytes| signing_key.sign(bytes).to_bytes().to_vec(),
        );

        let result = RelayDescriptorRecordBuilder::verify(&record, |msg, sig| {
            let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
                return false;
            };
            verifying_key
                .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                .is_ok()
        });
        assert!(result.is_ok());
    }
}
