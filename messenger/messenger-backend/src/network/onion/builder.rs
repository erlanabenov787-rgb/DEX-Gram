//! Строит цепочку relay-узлов (circuit) для onion-пакета. Выбор узлов —
//! ответственность relay/scoring.rs (кто надёжный, кто нет), этот файл
//! только оборачивает уже выбранный список в структуру с ephemeral
//! ключами для каждого хопа.

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::constants::{ONION_MAX_HOPS, ONION_MIN_HOPS};
use crate::errors::{MessengerError, Result};
use crate::network::onion::OnionHop;
use crate::types::DestinationHint;

/// Собранная цепочка: список хопов в порядке прохождения (guard первым,
/// exit последним) плюс наши ephemeral-ключи для каждого — нужны чтобы
/// каждый relay мог сделать DH с нами и получить ключ для своего слоя,
/// не зная кто мы (ephemeral, не наш identity-ключ).
pub struct OnionCircuit {
    pub hops: Vec<OnionHop>,
    /// `Option` потому что diffie_hellman() в x25519-dalek 2.x требует
    /// владения EphemeralSecret по значению (это фича, не баг библиотеки —
    /// не даёт случайно переиспользовать один ephemeral дважды). Каждый
    /// секрет вынимается ровно один раз через `take_ephemeral_secret`,
    /// когда wrap_layers шифрует слой для этого хопа.
    ephemeral_secrets: Vec<Option<EphemeralSecret>>,
    /// Публичные ключи считаем один раз при сборке цепочки и кэшируем
    /// отдельно — потому что после `take()` секрета его public уже не
    /// достать, а он может понадобиться для логов/отладки уже после
    /// того как пакет отправлен.
    ephemeral_publics: Vec<PublicKey>,
    pub destination: DestinationHint,
}

impl OnionCircuit {
    pub fn ephemeral_public_for_hop(&self, index: usize) -> PublicKey {
        self.ephemeral_publics[index]
    }

    /// Забирает EphemeralSecret для хопа по значению — можно вызвать
    /// только один раз на хоп, второй вызов вернёт `None`. wrap_layers
    /// вызывает это ровно по разу на каждый хоп при построении пакета.
    pub fn take_ephemeral_secret(&mut self, index: usize) -> Option<EphemeralSecret> {
        self.ephemeral_secrets[index].take()
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

/// Строит цепочку из уже выбранных relay-узлов. Валидирует длину
/// (ONION_MIN_HOPS..=ONION_MAX_HOPS) — короче не даёт анонимности,
/// длиннее не даёт прироста но добавляет задержку, так что и то и то
/// отклоняем на этом уровне, а не полагаемся на то что вызывающий код
/// всегда передаст правильное число хопов.
pub fn build_circuit(
    selected_hops: Vec<OnionHop>,
    destination: DestinationHint,
) -> Result<OnionCircuit> {
    if selected_hops.len() < ONION_MIN_HOPS {
        return Err(MessengerError::OnionChainTooShort {
            min: ONION_MIN_HOPS,
            got: selected_hops.len(),
        });
    }
    if selected_hops.len() > ONION_MAX_HOPS {
        // Не ошибка в смысле "нельзя продолжать", просто обрезаем —
        // вызывающий код (relay/scoring.rs) сам решает сколько узлов
        // предлагать, но на всякий случай не даём случайно раздуть
        // цепочку до 50 хопов из-за бага выше по стеку.
        let mut hops = selected_hops;
        hops.truncate(ONION_MAX_HOPS);
        return build_circuit(hops, destination);
    }

    let secrets: Vec<EphemeralSecret> = selected_hops
        .iter()
        .map(|_| EphemeralSecret::random_from_rng(OsRng))
        .collect();
    // Публичные ключи считаем до того, как секреты уйдут в Option —
    // после этого PublicKey::from(&secret) больше недоступен по ссылке
    // как только секрет будет take()-нут при шифровании слоя.
    let ephemeral_publics = secrets.iter().map(PublicKey::from).collect();
    let ephemeral_secrets = secrets.into_iter().map(Some).collect();

    Ok(OnionCircuit {
        hops: selected_hops,
        ephemeral_secrets,
        ephemeral_publics,
        destination,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::onion::OnionHop;

    fn fake_hop(id: &str) -> OnionHop {
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        OnionHop {
            relay_id: id.to_string(),
            onion_key: PublicKey::from(&sk),
        }
    }

    #[test]
    fn rejects_too_short_chain() {
        let hops = vec![fake_hop("a"), fake_hop("b")]; // только 2, нужно 3+
        let result = build_circuit(hops, DestinationHint::Mailbox("bob".to_string()));
        assert!(matches!(
            result,
            Err(MessengerError::OnionChainTooShort { .. })
        ));
    }

    #[test]
    fn accepts_valid_chain() {
        let hops = vec![fake_hop("a"), fake_hop("b"), fake_hop("c")];
        let circuit = build_circuit(hops, DestinationHint::Mailbox("bob".to_string())).unwrap();
        assert_eq!(circuit.len(), 3);
    }
}
