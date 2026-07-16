//! Общие мелкие типы, которые нужны и session/, и network/, и storage/ —
//! чтобы не тащить их друг у друга и не плодить дублирующиеся структуры.

use serde::{Deserialize, Serialize};

use crate::identity::UserId;

/// Идентификатор конкретной сессии Double Ratchet с конкретным
/// собеседником. Один UserId может в будущем иметь несколько сессий
/// (multi-device), поэтому это не просто alias на UserId.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn for_peer(peer: &UserId) -> Self {
        // Однодевайсовый MVP: один peer = одна сессия. При добавлении
        // multi-device сюда добавится device_id в состав ключа.
        Self(peer.clone())
    }
}

/// Направление сообщения относительно текущего узла — нужно и в
/// mailbox (что отдавать при опросе), и в session (какой ratchet
/// шаг применять).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Outgoing,
    Incoming,
}

/// Готовый к отправке пакет: onion-обёрнутый ciphertext плюс метаданные
/// маршрутизации, которые видит только сеть relay-узлов (не собеседник).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutedPacket {
    pub payload: Vec<u8>,
    pub destination_hint: DestinationHint,
}

/// То, что relay-узел обязан знать чтобы передать пакет дальше,
/// и ничего больше — конкретный получатель скрыт за слоями onion,
/// кроме последнего (exit) узла, который видит только mailbox-адрес,
/// но не личность отправителя.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DestinationHint {
    /// Прямая доставка живому p2p-соединению.
    DirectPeer(String), // PeerId в виде строки, чтобы не тащить libp2p в types.rs
    /// Отложенная доставка через mailbox (получатель оффлайн).
    Mailbox(UserId),
}

/// Результат попытки доставки — используется и в session manager
/// (решить, переотправлять ли), и в services/sync (метрики).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    DeliveredDirect,
    QueuedInMailbox,
    Failed(String),
}
