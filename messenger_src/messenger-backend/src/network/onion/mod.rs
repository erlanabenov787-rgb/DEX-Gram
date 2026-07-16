//! Onion routing поверх relay-сети: пакет заворачивается в N слоёв
//! шифрования (по одному на каждый узел цепочки guard→middle→exit),
//! каждый relay снимает только свой слой и не знает ни исходного
//! отправителя (кроме guard-узла, который видит IP, но не содержимое
//! дальше своего слоя), ни конечного адресата (кроме exit-узла,
//! который видит mailbox-адрес, но не отправителя).
//!
//! Это ортогонально E2E-шифрованию из crypto/ratchet.rs: даже exit-узел
//! видит только уже зашифрованный EncryptedEnvelope внутри своего слоя,
//! он не может прочитать содержимое сообщения — только доставить его.

pub mod builder;
pub mod decrypt;
pub mod encrypt;

pub use builder::{build_circuit, OnionCircuit};
pub use decrypt::peel_layer;
// NB: wrap_layers принимает &mut OnionCircuit — он потребляет ephemeral
// секреты каждого хопа по значению (см. builder::take_ephemeral_secret),
// поэтому circuit нельзя переиспользовать для второго пакета после вызова.
pub use encrypt::wrap_layers;

use serde::{Deserialize, Serialize};

/// Публичный ключ relay-узла для onion-слоя — используем X25519,
/// отдельный keypair от того что relay использует для libp2p-транспорта
/// (тот шифрует канал до следующего хопа, этот — шифрует данные для
/// конкретного узла независимо от пути до него).
pub type RelayOnionKey = x25519_dalek::PublicKey;

/// Один узел в onion-цепочке — то, что нужно builder'у чтобы завернуть
/// слой именно для него.
#[derive(Debug, Clone)]
pub struct OnionHop {
    pub relay_id: crate::network::RelayId,
    pub onion_key: RelayOnionKey,
}

/// Пакет после всех слоёв onion-шифрования — то, что физически летит
/// по libp2p-соединению до guard-узла.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    pub layers: Vec<u8>, // вложенные зашифрованные слои, самый внешний снаружи
}

/// Результат снятия одного слоя одним relay-узлом.
pub enum PeelResult {
    /// Есть ещё слои — вот следующий relay_id, кому это переслать,
    /// и оставшийся (ещё зашифрованный) пакет для него.
    Forward {
        next_hop: crate::network::RelayId,
        remaining: OnionPacket,
    },
    /// Это был последний (exit) слой — вот итоговая полезная нагрузка
    /// (EncryptedEnvelope в сериализованном виде) и адрес доставки.
    Exit {
        payload: Vec<u8>,
        destination: crate::types::DestinationHint,
    },
}
