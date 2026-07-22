//! Единый тип ошибок для всего крейта. Локальные модули могут временно
//! использовать anyhow::Result внутри себя (особенно crypto/, где
//! stacktrace важнее типизации), но всё, что пересекает границу
//! session/ <-> network/ <-> services/, должно возвращать MessengerError,
//! чтобы вызывающий код мог разбирать причину (например "нет сессии" —
//! это повод запустить X3DH, а не падать).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessengerError {
    #[error("нет активной сессии с {0}")]
    NoSession(crate::identity::UserId),

    #[error("сессия с {0} уже существует")]
    SessionAlreadyExists(crate::identity::UserId),

    #[error("сообщение пришло не по порядку: ожидали counter {expected}, получили {got}")]
    OutOfOrderMessage { expected: u32, got: u32 },

    #[error("ошибка шифрования/дешифрования: {0}")]
    Crypto(String),

    #[error("prekey bundle для {0} не найден в DHT")]
    PreKeyBundleNotFound(crate::identity::UserId),

    #[error("подпись signed prekey недействительна для {0}")]
    InvalidPreKeySignature(crate::identity::UserId),

    #[error("подпись сообщения от {0} недействительна — возможно MITM или повреждённый пакет")]
    InvalidMessageSignature(crate::identity::UserId),

    #[error("identity-ключ (для проверки подписи) не найден для {0}")]
    IdentityKeyNotFound(crate::identity::UserId),

    #[error("envelope заявляет отправителя {claimed}, но использовался в контексте сессии с {expected}")]
    SenderMismatch { claimed: crate::identity::UserId, expected: crate::identity::UserId },

    #[error("onion-цепочка должна содержать минимум {min} узла, дано {got}")]
    OnionChainTooShort { min: usize, got: usize },

    #[error("не удалось развернуть onion-слой: {0}")]
    OnionUnwrap(String),

    #[error("relay {0} отклонил пакет: {1}")]
    RelayRejected(crate::network::RelayId, String),

    #[error("mailbox переполнен для {user} (лимит {limit} сообщений)")]
    MailboxFull { user: crate::identity::UserId, limit: usize },

    #[error("onion-ключ для relay {0} не найден")]
    OnionKeyNotFound(crate::network::RelayId),

    #[error("запись в DHT не найдена: {0}")]
    DhtRecordNotFound(String),

    #[error("хранилище: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("сеть (libp2p): {0}")]
    Network(String),

    #[error("сериализация протокола: {0}")]
    Protocol(#[from] prost::DecodeError),

    #[error("сериализация: {0}")]
    Serialization(String),

    #[error("таймаут ожидания ответа")]
    Timeout,

    #[error("неизвестная ошибка: {0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, MessengerError>;
