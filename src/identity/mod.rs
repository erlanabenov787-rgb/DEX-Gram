//! Identity = keypair. UserID = base58(SHA256(PublicKey))[..20 bytes],
//! человекочитаемый, детерминированный, без центрального реестра.
//!
//! ПРИМЕЧАНИЕ: раньше это лежало в плоском identity.rs. Кто-то начал
//! разносить это на identity/keys.rs + identity/prekeys.rs +
//! identity/user_id.rs, но эти файлы так и не были созданы — mod.rs
//! ссылался на несуществующие submodules, из-за чего проект вообще не
//! мог собраться (E0583). Пока держим всё в одном mod.rs как рабочий
//! вариант; разбивку на подмодули можно сделать позже отдельным шагом,
//! когда реально понадобится (например, prekeys.rs — для one-time
//! prekeys, PREKEY_BATCH_SIZE в constants.rs уже на это намекает).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub type UserId = String;

pub struct Identity {
    signing_key: SigningKey, // приватный ключ — держим внутри, наружу не отдаём
    pub verifying_key: VerifyingKey, // публичный ключ
    pub user_id: UserId,
}

impl Identity {
    /// Генерирует новую личность с нуля.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_signing_key(signing_key)
    }

    /// Восстанавливает личность из приватного ключа (например, после
    /// разбора recovery phrase).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let user_id = Self::derive_user_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            user_id,
        }
    }

    fn derive_user_id(vk: &VerifyingKey) -> UserId {
        let hash = Sha256::digest(vk.as_bytes());
        // Берём первые 20 байт хэша публичного ключа — этого достаточно
        // для практической коллизионной стойкости и делает ID короче.
        bs58::encode(&hash[..20]).into_string()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(vk: &VerifyingKey, message: &[u8], sig: &Signature) -> bool {
        vk.verify(message, sig).is_ok()
    }

    /// То же самое, что `verify`, но берёт подпись как сырые байты (как
    /// она приходит по сети/из хранилища, например `EncryptedEnvelope::sender_signature`).
    /// Возвращает `false` вместо паники на мусорном/неверной длины входе —
    /// приём чужих данных не должен уметь ронять процесс.
    pub fn verify_bytes(vk: &VerifyingKey, message: &[u8], sig_bytes: &[u8]) -> bool {
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);
        Self::verify(vk, message, &sig)
    }

    /// Парсит verifying key из сырых 32 байт (как она лежит в БД контактов
    /// или в `DhtRecord::public_key`). `None` на мусорном входе вместо паники.
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> Option<VerifyingKey> {
        let arr = <[u8; 32]>::try_from(bytes).ok()?;
        VerifyingKey::from_bytes(&arr).ok()
    }

    /// Экспорт приватного ключа для recovery phrase (BIP39-подобно).
    /// ВАЖНО: вызывающий код обязан обнулить байты после использования.
    pub fn export_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn from_secret_bytes(mut bytes: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        Self::from_signing_key(sk)
    }
}

/// Recovery phrase — обёртка над bip39, генерируется опционально при
/// регистрации. Пользователь сам решает, включать её или жить в режиме
/// "потерял ключ — потерял аккаунт".
pub mod recovery {
    use super::Identity;
    use bip39::{Language, Mnemonic};
    use rand_core::{OsRng, RngCore};

    pub fn generate() -> (Mnemonic, Identity) {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .expect("32 bytes is valid entropy length");
        let identity = Identity::from_secret_bytes(entropy);
        (mnemonic, identity)
    }

    pub fn restore(phrase: &str) -> anyhow::Result<Identity> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)?;
        let entropy = mnemonic.to_entropy();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&entropy[..32]);
        Ok(Identity::from_secret_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_is_deterministic() {
        let id1 = Identity::generate();
        let id2 = Identity::from_secret_bytes(id1.export_secret_bytes());
        assert_eq!(id1.user_id, id2.user_id);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let identity = Identity::generate();
        let msg = b"hello relay";
        let sig = identity.sign(msg);
        assert!(Identity::verify(&identity.verifying_key, msg, &sig));
    }
}
