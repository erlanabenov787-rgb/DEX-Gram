pub mod pow;
pub mod ratchet;
pub mod x3dh;

pub use ratchet::{DoubleRatchet, RatchetRole, RatchetState};
pub use x3dh::X3dhSession;

/// Единый формат зашифрованного конверта, который гуляет по сети.
/// Всё, что relay видит снаружи — это `nonce` + `ciphertext`, содержимое
/// (тип сообщения, текст, вложения) целиком внутри ciphertext.
///
/// ЧЕСТНО про `sender_id`/`sender_signature`: `protocol::Packet` (см.
/// message.proto) не несёт поля отправителя вообще, поэтому раньше
/// `SessionManager::decrypt_message` физически не мог понять, чью
/// ratchet-сессию использовать — это и была причина, почему подпись
/// никто не проверял (см. предыдущий TODO). Кладём sender_id сюда, а
/// не в Packet, чтобы не трогать .proto. Побочный эффект: относящийся
/// к сообщению exit-relay/mailbox узел, который физически держит эти
/// байты между onion-exit и выдачей получателю, теоретически может
/// прочитать эти два поля (они не под отдельным слоем шифрования) —
/// то есть личность отправителя не защищена от него так же строго,
/// как раньше был защищён counter. Для полной metadata-защиты это
/// стоит вынести под собственный AEAD-слой позже; сейчас это
/// осознанный компромисс ради того, чтобы подписи вообще заработали.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedEnvelope {
    /// Кто отправил — по этому полю получатель находит нужную
    /// ratchet-сессию в SessionManager, без него decrypt_message не мог
    /// работать в принципе (peer было неоткуда взять).
    pub sender_id: crate::identity::UserId,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    /// Номер сообщения в ratchet-цепочке — нужен получателю чтобы
    /// синхронизировать ключи, но сам по себе бессмысленен для relay.
    pub counter: u32,
    /// ed25519-подпись отправителя над signable_bytes() (см. ниже) его
    /// identity-ключом (см. identity/mod.rs — это отдельный ключ от
    /// x3dh_identity, использующегося для DH). Проверяется получателем
    /// ДО того как ratchet вообще пытается расшифровать — так
    /// порченный/подделанный пакет отбрасывается раньше, чем тратится
    /// ключ ratchet-цепочки на него.
    pub sender_signature: Vec<u8>,
    /// Присутствует ТОЛЬКО в первом сообщении новой сессии — несёт всё,
    /// что нужно получателю (Бобу) чтобы досчитать тот же X3DH-секрет,
    /// что уже посчитал инициатор (Алиса) в
    /// `SessionManager::ensure_session_as_initiator`. Раньше этого поля
    /// просто не было: `SessionManager::decrypt_message` не мог принять
    /// первое сообщение от нового собеседника вообще, потому что
    /// эфемерный X25519-ключ инициатора было негде передать — см.
    /// `SessionManager::accept_incoming_session`, который теперь читает
    /// именно это поле. `None` для всех последующих сообщений в этой же
    /// ratchet-цепочке.
    pub session_init: Option<SessionInit>,
}

/// X3DH-параметры первого сообщения новой сессии — ровно то, чего не
/// хватало получателю, чтобы пересчитать shared_secret инициатора
/// (см. `crypto::x3dh::X3dhSession::respond`).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionInit {
    /// Эфемерный X25519-публичный ключ инициатора (alice_ephemeral_public
    /// из `X3dhSession::initiate`) — нужен получателю для DH2/DH3/DH4.
    pub ephemeral_key: [u8; 32],
    /// Публичный ключ one-time prekey получателя, который инициатор
    /// израсходовал для DH4 (см. `PreKeyBundle::one_time_prekey`).
    /// Используем сам публичный ключ, а не индекс в пуле — так получателю
    /// не нужно полагаться на то, что порядок его локального пула
    /// совпадает с порядком, в котором ключи были опубликованы/прочитаны
    /// инициатором на момент фетча бандла (пул мог быть частично
    /// израсходован другими сессиями между публикацией и этим приёмом).
    /// `None`, если у инициатора на момент фетча бандла не было
    /// доступного one-time prekey (DH4 не использовался).
    pub one_time_prekey_public: Option<[u8; 32]>,
}

impl EncryptedEnvelope {
    /// Канонический набор байт, который подписывается/проверяется.
    /// Порядок полей фиксирован и не должен меняться без версионирования.
    /// `session_init`, если есть, подписывается тоже — иначе активный
    /// MITM мог бы подменить эфемерный ключ/OTPK инициатора, не трогая
    /// саму подпись (последствие — сорванная сессия у настоящих
    /// участников, а не утечка контента, но это всё равно нарушение
    /// целостности, которое дёшево закрыть).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.sender_id.len() + 12 + 4 + self.ciphertext.len() + 33);
        buf.extend_from_slice(self.sender_id.as_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.counter.to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        if let Some(init) = &self.session_init {
            buf.push(1);
            buf.extend_from_slice(&init.ephemeral_key);
            match init.one_time_prekey_public {
                Some(otpk) => {
                    buf.push(1);
                    buf.extend_from_slice(&otpk);
                }
                None => buf.push(0),
            }
        } else {
            buf.push(0);
        }
        buf
    }
}
