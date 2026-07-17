//! Состояние одной E2E-сессии с конкретным собеседником: обёртка над
//! DoubleRatchet + метаданные, нужные чтобы session/manager.rs мог
//! принимать решения (переустановить сессию, пометить устаревшей и т.д.)
//! без залезания во внутренности crypto/.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{DoubleRatchet, EncryptedEnvelope, RatchetRole, RatchetState};
use crate::identity::UserId;
use crate::types::SessionId;

/// Откуда взялась сессия — влияет на то, кто должен был отправить
/// первое X3DH-сообщение, и полезно для отладки/логов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionOrigin {
    /// Мы инициировали (Alice в терминах X3DH).
    Initiated,
    /// Приняли входящую сессию (Bob в терминах X3DH).
    Accepted,
}

pub struct Session {
    pub id: SessionId,
    pub peer: UserId,
    pub origin: SessionOrigin,
    ratchet: DoubleRatchet,
    pub created_at: u64,
    pub last_used_at: u64,
    /// Счётчик сообщений отправленных за всё время жизни сессии —
    /// не путать с counter внутри DoubleRatchet (тот сбрасывается
    /// логически при DH-ratchet шаге, которого пока нет в MVP,
    /// см. crypto/ratchet.rs, этот — просто для метрик/UI "N сообщений").
    pub messages_sent: u64,
    pub messages_received: u64,
}

impl Session {
    pub fn new(peer: UserId, origin: SessionOrigin, root_secret: [u8; 32]) -> Self {
        let now = now_unix();
        Self {
            id: SessionId::for_peer(&peer),
            peer,
            origin,
            ratchet: DoubleRatchet::new(root_secret, Self::role_for_origin(origin)),
            created_at: now,
            last_used_at: now,
            messages_sent: 0,
            messages_received: 0,
        }
    }

    /// RatchetRole (см. crypto/ratchet.rs) детерминированно вытекает из
    /// SessionOrigin: кто X3DH-инициировал сессию — тот же, кто физически
    /// является "Initiator" для выбора send/recv-цепочек. Обе стороны
    /// одной сессии всегда имеют противоположные origin (Initiated у
    /// одной = Accepted у другой), поэтому противоположные роли им
    /// гарантированы автоматически.
    fn role_for_origin(origin: SessionOrigin) -> RatchetRole {
        match origin {
            SessionOrigin::Initiated => RatchetRole::Initiator,
            SessionOrigin::Accepted => RatchetRole::Responder,
        }
    }

    /// Восстанавливает сессию из реального сохранённого состояния (см.
    /// storage/session_store.rs) вместо Session::new(root_secret), который
    /// ВСЕГДА обнулял бы counter'ы/ключи цепочки заново — раньше именно
    /// так и происходило при каждой загрузке из БД (SqliteSessionStore::load
    /// звал Session::new с нулевым root_secret-плейсхолдером), из-за чего
    /// расшифровка входящих сообщений после любого рестарта приложения
    /// была сломана (получатель "думал", что разговор начинается с нуля,
    /// хотя у собеседника ratchet давно продвинут дальше).
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        peer: UserId,
        origin: SessionOrigin,
        ratchet_state: RatchetState,
        created_at: u64,
        last_used_at: u64,
        messages_sent: u64,
        messages_received: u64,
    ) -> Self {
        Self {
            id: SessionId::for_peer(&peer),
            peer,
            origin,
            ratchet: DoubleRatchet::restore(ratchet_state),
            created_at,
            last_used_at,
            messages_sent,
            messages_received,
        }
    }

    /// Снимок текущего ratchet-состояния для сохранения (см.
    /// SqliteSessionStore::save) — заменяет старый плейсхолдер
    /// `[0u8;32]`, который раньше писался вместо реального состояния.
    pub fn export_ratchet_state(&self) -> RatchetState {
        self.ratchet.export_state()
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> crate::errors::Result<EncryptedEnvelope> {
        let envelope = self
            .ratchet
            .encrypt(plaintext)
            .map_err(|e| crate::errors::MessengerError::Crypto(e.to_string()))?;
        self.messages_sent += 1;
        self.last_used_at = now_unix();
        Ok(envelope)
    }

    pub fn decrypt(&mut self, envelope: &EncryptedEnvelope) -> crate::errors::Result<Vec<u8>> {
        let plaintext = self
            .ratchet
            .decrypt(envelope)
            .map_err(|e| crate::errors::MessengerError::Crypto(e.to_string()))?;
        self.messages_received += 1;
        self.last_used_at = now_unix();
        Ok(plaintext)
    }

    /// Сессия считается "протухшей", если ей не пользовались дольше
    /// заданного окна — session manager может решить пересогласовать
    /// её через новый X3DH вместо того чтобы продолжать древнюю цепочку.
    pub fn is_stale(&self, max_idle_secs: u64) -> bool {
        now_unix().saturating_sub(self.last_used_at) > max_idle_secs
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("часы должны идти после 1970 года")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrip() {
        let secret = [7u8; 32];
        let mut alice = Session::new("bob".to_string(), SessionOrigin::Initiated, secret);
        let mut bob = Session::new("alice".to_string(), SessionOrigin::Accepted, secret);

        let envelope = alice.encrypt(b"privet").unwrap();
        let plaintext = bob.decrypt(&envelope).unwrap();

        assert_eq!(plaintext, b"privet");
        assert_eq!(alice.messages_sent, 1);
        assert_eq!(bob.messages_received, 1);
    }

    #[test]
    fn fresh_session_is_not_stale() {
        let session = Session::new("bob".to_string(), SessionOrigin::Initiated, [0u8; 32]);
        assert!(!session.is_stale(60));
    }
}
