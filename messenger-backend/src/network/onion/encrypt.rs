//! Заворачивает payload в слои шифрования от exit-узла к guard-узлу
//! (в обратном порядке прохождения) — так что когда пакет физически
//! летит guard→middle→exit, каждый узел снимает ровно один слой и видит
//! ровно то, что ему причитается: следующий hop или (для exit) финальный
//! payload+адрес.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::PublicKey;

use crate::constants::ONION_CELL_SIZE;
use crate::errors::{MessengerError, Result};
use crate::network::onion::{OnionCircuit, OnionPacket};
use crate::types::DestinationHint;

/// Что зашифровано внутри одного слоя — либо "вот следующий хоп и
/// зашифрованные для него данные", либо (для самого внутреннего слоя,
/// который снимет exit-узел) финальный payload.
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

/// Заголовок слоя: наш ephemeral public key для этого хопа (relay
/// делает DH(их приватный onion_key, этот ephemeral public) чтобы
/// получить симметричный ключ слоя) + nonce + ciphertext.
#[derive(Serialize, Deserialize)]
struct Layer {
    ephemeral_public: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

pub fn wrap_layers(circuit: &mut OnionCircuit, payload: Vec<u8>) -> Result<OnionPacket> {
    if circuit.is_empty() {
        return Err(MessengerError::OnionChainTooShort { min: 1, got: 0 });
    }

    // Начинаем с самого внутреннего содержимого (то что увидит exit-узел)
    // и наращиваем слои снаружи по мере движения к guard-узлу — то есть
    // итерируем хопы в обратном порядке.
    let mut current = bincode::serialize(&LayerContent::Exit {
        payload,
        destination: circuit.destination.clone(),
    })
    .map_err(|e| MessengerError::OnionUnwrap(format!("serialize exit layer: {e}")))?;

    pad_to_cell_size(&mut current);

    let last_index = circuit.len() - 1;
    for i in (0..circuit.len()).rev() {
        let hop_public = circuit.hops[i].onion_key;
        let layer_content = if i == last_index {
            current
        } else {
            let next_hop_id = circuit.hops[i + 1].relay_id.clone();
            let wrapped = LayerContent::Forward {
                next_hop: next_hop_id,
                inner: current,
            };
            bincode::serialize(&wrapped)
                .map_err(|e| MessengerError::OnionUnwrap(format!("serialize forward layer: {e}")))?
        };

        // take() — секрет этого хопа используется ровно один раз за
        // время жизни circuit, что и требует API x25519-dalek для DH.
        let ephemeral_secret = circuit.take_ephemeral_secret(i).ok_or_else(|| {
            MessengerError::OnionUnwrap(format!(
                "ephemeral secret для хопа {i} уже использован — \
                 wrap_layers вызван дважды на одной цепочке?"
            ))
        })?;

        current = encrypt_layer_for_hop(hop_public, ephemeral_secret, &layer_content)?;
    }

    Ok(OnionPacket { layers: current })
}

fn encrypt_layer_for_hop(
    hop_public: PublicKey,
    ephemeral_secret: x25519_dalek::EphemeralSecret,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    // diffie_hellman() требует владения `self` по значению — вот почему
    // ephemeral_secret приходит сюда через take() из OnionCircuit, а не
    // по ссылке: библиотека нарочно не даёт использовать один и тот же
    // ephemeral ключ дважды (защита от повторного использования между
    // разными пакетами).
    let shared = ephemeral_secret.diffie_hellman(&hop_public);

    let symmetric_key = derive_layer_key(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&symmetric_key));

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| MessengerError::Crypto(format!("onion layer encrypt: {e}")))?;

    let layer = Layer {
        ephemeral_public: ephemeral_public.to_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    };

    bincode::serialize(&layer)
        .map_err(|e| MessengerError::OnionUnwrap(format!("serialize layer envelope: {e}")))
}

fn derive_layer_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"onion-layer-v1", &mut key)
        .expect("32 bytes valid HKDF length");
    key
}

fn pad_to_cell_size(data: &mut Vec<u8>) {
    if data.len() < ONION_CELL_SIZE {
        data.resize(ONION_CELL_SIZE, 0);
    }
    // Если payload больше ONION_CELL_SIZE, это ответственность
    // dispatcher.rs — резать сообщение на чанки перед onion-обёрткой
    // (см. constants::MAX_MESSAGE_SIZE_BYTES), здесь мы это не решаем
    // молча усечением данных.
}
