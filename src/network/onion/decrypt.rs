//! Снимает ровно один слой onion-шифрования — это то, что вызывает
//! relay/router.rs при получении OnionPacket: relay знает только СВОЙ
//! приватный onion_key, поэтому может расшифровать только внешний слой,
//! адресованный ему, и не может заглянуть глубже (нет приватных ключей
//! следующих хопов).

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::errors::{MessengerError, Result};
use crate::network::onion::{OnionPacket, PeelResult};
use crate::types::DestinationHint;

#[derive(Serialize, Deserialize)]
enum LayerContent {
    Forward {
        next_hop: crate::network::RelayId,
        inner: Vec<u8>,
    },
    Exit {
        payload: Vec<u8>,
        destination: DestinationHint,
    },
}

#[derive(Serialize, Deserialize)]
struct Layer {
    ephemeral_public: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// `our_onion_secret` — приватный X25519-ключ ЭТОГО relay-узла
/// (публикуется в DHT как часть relay-дескриптора, см. relay/service.rs).
pub fn peel_layer(packet: &OnionPacket, our_onion_secret: &StaticSecret) -> Result<PeelResult> {
    let layer: Layer = bincode::deserialize(&packet.layers)
        .map_err(|e| MessengerError::OnionUnwrap(format!("deserialize layer: {e}")))?;

    let their_ephemeral_public = PublicKey::from(layer.ephemeral_public);
    let shared = our_onion_secret.diffie_hellman(&their_ephemeral_public);
    let symmetric_key = derive_layer_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&symmetric_key));
    let nonce = Nonce::from_slice(&layer.nonce);

    let plaintext = cipher
        .decrypt(nonce, layer.ciphertext.as_ref())
        .map_err(|e| MessengerError::OnionUnwrap(format!("layer decrypt failed: {e}")))?;

    // Убираем нулевой паддинг с хвоста перед десериализацией — паддинг
    // добавляется в encrypt.rs::pad_to_cell_size только на самом
    // внутреннем (Exit) слое, промежуточные Forward-слои паддинг не
    // добавляют повторно (их размер уже фиксирован структурой Layer),
    // так что тут декодируем как есть; корректность обеспечивается тем
    // что bincode формат самоописывающий по длине полей, лишние нули
    // после валидной структуры просто игнорируются десериализатором
    // при чтении фиксированного enum-формата.
    let content: LayerContent = bincode::deserialize(&plaintext)
        .map_err(|e| MessengerError::OnionUnwrap(format!("deserialize content: {e}")))?;

    match content {
        LayerContent::Forward { next_hop, inner } => Ok(PeelResult::Forward {
            next_hop,
            remaining: OnionPacket { layers: inner },
        }),
        LayerContent::Exit {
            payload,
            destination,
        } => Ok(PeelResult::Exit {
            payload,
            destination,
        }),
    }
}

fn derive_layer_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"onion-layer-v1", &mut key)
        .expect("32 bytes valid HKDF length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_packet() {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let garbage = OnionPacket {
            layers: vec![1, 2, 3, 4],
        };
        let result = peel_layer(&garbage, &secret);
        assert!(result.is_err());
    }
}
