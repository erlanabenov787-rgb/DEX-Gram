//! Упрощённый X3DH (Extended Triple Diffie-Hellman) — устанавливает
//! общий секрет между Алисой и Бобом даже если Боб оффлайн, используя
//! его заранее опубликованные ключи из DHT (identity key + signed
//! prekey + one-time prekey).
//!
//! ВАЖНО: для продакшена лучше взять готовую реализацию (например
//! крейт `x3dh` или libsignal-биндинги) вместо самодельной — здесь
//! упрощённая версия для понимания потока данных и для MVP.

use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Публичный "бандл" ключей, который Боб публикует в своей DHT-записи,
/// чтобы Алиса могла начать с ним переписку даже пока он оффлайн.
pub struct PreKeyBundle {
    pub identity_key: PublicKey,
    pub signed_prekey: PublicKey,
    pub signed_prekey_signature: Vec<u8>, // подпись ed25519 identity-ключом
    pub one_time_prekey: Option<PublicKey>,
}

pub struct X3dhSession {
    pub shared_secret: [u8; 32],
}

impl X3dhSession {
    /// Алиса инициирует сессию с опубликованным бандлом Боба.
    pub fn initiate(
        alice_identity: &StaticSecret,
        bob_bundle: &PreKeyBundle,
    ) -> (Self, PublicKey /* ephemeral key, шлём Бобу */) {
        let alice_ephemeral = StaticSecret::random_from_rng(OsRng);
        let alice_ephemeral_public = PublicKey::from(&alice_ephemeral);

        // DH1: identity_A × signed_prekey_B
        let dh1 = alice_identity.diffie_hellman(&bob_bundle.signed_prekey);
        // DH2: ephemeral_A × identity_B
        let dh2 = alice_ephemeral.diffie_hellman(&bob_bundle.identity_key);
        // DH3: ephemeral_A × signed_prekey_B
        let dh3 = alice_ephemeral.diffie_hellman(&bob_bundle.signed_prekey);
        // DH4 (опционально, если есть one-time prekey): ephemeral_A × otpk_B
        let dh4 = bob_bundle
            .one_time_prekey
            .map(|otpk| alice_ephemeral.diffie_hellman(&otpk));

        let shared_secret = Self::derive_key(&dh1, &dh2, &dh3, dh4.as_ref());

        (Self { shared_secret }, alice_ephemeral_public)
    }

    /// Боб принимает первое сообщение и восстанавливает тот же секрет.
    pub fn respond(
        bob_identity: &StaticSecret,
        bob_signed_prekey: &StaticSecret,
        bob_one_time_prekey: Option<&StaticSecret>,
        alice_identity_public: &PublicKey,
        alice_ephemeral_public: &PublicKey,
    ) -> Self {
        let dh1 = bob_signed_prekey.diffie_hellman(alice_identity_public);
        let dh2 = bob_identity.diffie_hellman(alice_ephemeral_public);
        let dh3 = bob_signed_prekey.diffie_hellman(alice_ephemeral_public);
        let dh4 = bob_one_time_prekey.map(|otpk| otpk.diffie_hellman(alice_ephemeral_public));

        let shared_secret = Self::derive_key(&dh1, &dh2, &dh3, dh4.as_ref());
        Self { shared_secret }
    }

    fn derive_key(
        dh1: &x25519_dalek::SharedSecret,
        dh2: &x25519_dalek::SharedSecret,
        dh3: &x25519_dalek::SharedSecret,
        dh4: Option<&x25519_dalek::SharedSecret>,
    ) -> [u8; 32] {
        let mut ikm = Vec::with_capacity(32 * 4);
        ikm.extend_from_slice(dh1.as_bytes());
        ikm.extend_from_slice(dh2.as_bytes());
        ikm.extend_from_slice(dh3.as_bytes());
        if let Some(dh4) = dh4 {
            ikm.extend_from_slice(dh4.as_bytes());
        }

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"messenger-x3dh-v1", &mut okm)
            .expect("32 bytes is a valid HKDF output length");

        ikm.zeroize();
        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alice_and_bob_derive_same_secret() {
        let alice_identity = StaticSecret::random_from_rng(OsRng);
        let bob_identity = StaticSecret::random_from_rng(OsRng);
        let bob_signed_prekey = StaticSecret::random_from_rng(OsRng);

        let bundle = PreKeyBundle {
            identity_key: PublicKey::from(&bob_identity),
            signed_prekey: PublicKey::from(&bob_signed_prekey),
            signed_prekey_signature: vec![], // не проверяем в тесте
            one_time_prekey: None,
        };

        let (alice_session, alice_ephemeral_pub) =
            X3dhSession::initiate(&alice_identity, &bundle);

        let bob_session = X3dhSession::respond(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &PublicKey::from(&alice_identity),
            &alice_ephemeral_pub,
        );

        assert_eq!(alice_session.shared_secret, bob_session.shared_secret);
    }
}
