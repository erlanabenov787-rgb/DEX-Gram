pub mod dispatcher;
pub mod dht;
pub mod mailbox;
pub mod onion;
pub mod p2p;
pub mod relay;
pub mod transport;

pub use p2p::{NodeCommand, NodeHandle};

/// Relay всегда обращается друг к другу по этому ID, а не по IP —
/// IP скрыт слоями onion routing, наружу торчит только это.
pub type RelayId = String;

/// Команда "реально отправь этот Packet такому-то PeerId по транспорту".
///
/// Зачем это нужно: relay/dispatcher-код (network/dispatcher.rs,
/// network/relay/service.rs) — это чистая логика без доступа к
/// libp2p Swarm (он живёт внутри p2p::NodeHandle и не может быть
/// передан как &mut одновременно с тем, что уже занято на время
/// обработки события). Поэтому вместо прямого вызова swarm.send —
/// эти модули кладут команду в канал, а NodeHandle сам вычитывает
/// её и реально отправляет через `send_packet`, когда управление
/// возвращается в event loop.
#[derive(Debug)]
pub struct OutboundPacket {
    pub target_peer_id: RelayId,
    pub packet: crate::protocol::Packet,
}

pub type OutboundSender = tokio::sync::mpsc::UnboundedSender<OutboundPacket>;
pub type OutboundReceiver = tokio::sync::mpsc::UnboundedReceiver<OutboundPacket>;

/// Успешно расшифрованное входящее сообщение, готовое к сохранению и
/// показу в UI. dispatcher.rs кладёт их сюда вместо того чтобы просто
/// логировать (см. старый TODO "сохранить в SQLite и/или прокинуть в UI
/// callback — сейчас только логируем").
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub from: crate::identity::UserId,
    pub plaintext: Vec<u8>,
}

pub type IncomingSender = tokio::sync::mpsc::UnboundedSender<IncomingMessage>;
pub type IncomingReceiver = tokio::sync::mpsc::UnboundedReceiver<IncomingMessage>;
