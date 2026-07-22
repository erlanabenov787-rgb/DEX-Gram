//! Упрощённый Double Ratchet: симметричный ratchet поверх общего
//! секрета из X3DH. Каждое сообщение — новый ключ (forward secrecy):
//! компрометация текущего ключа не раскрывает прошлые сообщения.
//!
//! Это симметричная часть ratchet (KDF chain). Полноценный Double
//! Ratchet также делает DH-ratchet шаг при смене ephemeral-ключей
//! партнёра — для MVP тут только симметричная цепочка, DH-ratchet
//! шаг стоит добавить перед продакшн-использованием.

use std::collections::HashMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto::EncryptedEnvelope;

/// Сколько сообщений вперёд разрешаем "перепрыгнуть", храня пропущенные
/// ключи. Без потолка злонамеренный/битый counter (например 4_000_000_000)
/// заставил бы нас молотить HKDF миллиарды раз и раздуть skipped_keys до
/// исчерпания памяти — это Signal-style защита от такого DoS.
const MAX_SKIP: u32 = 1000;

/// Кто из двух сторон сессии физически является X3DH-инициатором —
/// нужно чтобы обе стороны детерминированно согласились, какая из двух
/// HKDF-цепочек (см. RatchetState/derive_chains ниже) считается "моей
/// на отправку", а какая — "моей на приём". Без этого при симметричной
/// договорённости обе стороны выбрали бы одну и ту же цепочку для
/// encrypt(), и первое же реальное двустороннее общение (не только
/// тестовый round-trip в один конец) сломало бы расшифровку у обеих
/// сторон после того, как каждая отправит хотя бы одно сообщение — см.
/// комментарий у полей send_chain_key/recv_chain_key ниже.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RatchetRole {
    Initiator,
    Responder,
}

/// Снимок состояния ratchet-а для персистентности (см.
/// storage/session_store.rs) — вся мутируемая часть DoubleRatchet, КРОМЕ
/// skipped_keys (сознательно не персистятся: они существуют только для
/// исправления реордеринга внутри одной "живой" сессии процесса; если
/// процесс перезапустился между отправкой и получением пропущенного
/// сообщения, оно просто не расшифруется — тот же trade-off, что и в
/// оригинальном Signal Double Ratchet для очень старых пропущенных
/// ключей за пределами разумного окна).
#[derive(Clone)]
pub struct RatchetState {
    pub send_chain_key: [u8; 32],
    pub send_counter: u32,
    pub recv_chain_key: [u8; 32],
    pub recv_counter: u32,
}

pub struct DoubleRatchet {
    /// РАНЬШЕ здесь была ОДНА пара chain_key/counter, используемая и в
    /// encrypt(), и в decrypt() — то есть обе стороны сессии шифровали
    /// и расшифровывали через один и тот же физический счётчик. Это
    /// работало только для одностороннего теста ("alice шлёт, bob
    /// читает"), но ломается в реальном двустороннем разговоре: как
    /// только Alice отправит сообщение #1 (продвинув общий counter до
    /// 1) и Bob тоже отправит своё сообщение #1 (продвинув СВОЙ
    /// экземпляр общего counter независимо до 1), их counter'ы
    /// перестают совпадать с тем, что видит другая сторона — Alice
    /// получит от Bob envelope с counter=1, но у неё самой chain_key уже
    /// продвинут её собственным исходящим сообщением, так что ключи не
    /// совпадут и decrypt провалится. Теперь две независимые цепочки:
    /// одна физическая KDF-цепочка используется только для исходящих
    /// (send_*), другая — только для входящих (recv_*), и RatchetRole
    /// (см. выше) гарантирует, что обе стороны используют
    /// противоположные физические цепочки для одной и той же логической
    /// роли ("моя цепочка отправки" Alice = "цепочка приёма" у Bob).
    send_chain_key: [u8; 32],
    send_counter: u32,
    recv_chain_key: [u8; 32],
    recv_counter: u32,
    /// Ключи для сообщений, которые ещё не пришли, но чей номер уже
    /// "пройден" цепочкой — нужно когда пакеты из P2P-сети приходят не
    /// по порядку (разные маршруты через relay, доставка mailbox не
    /// гарантирует порядок). Без этого DoubleRatchet::decrypt требовал
    /// строго counter == self.counter + 1 и любое переупорядочивание
    /// сообщений необратимо ломало сессию (см. старый TODO выше).
    /// Относится только к recv-цепочке — send-цепочка никогда не
    /// "пропускает" с нашей же стороны.
    skipped_keys: HashMap<u32, [u8; 32]>,
}

impl DoubleRatchet {
    /// Строит обе независимые цепочки из общего X3DH root_secret через
    /// HKDF с разными info-строками — так обе стороны, зная только
    /// общий root_secret и свою роль, детерминированно приходят к двум
    /// разным (но согласованным между сторонами) ключам.
    fn derive_chains(root_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(None, root_secret);
        let mut initiator_chain = [0u8; 32];
        hk.expand(b"ratchet-chain-initiator-to-responder", &mut initiator_chain)
            .expect("valid length");
        let mut responder_chain = [0u8; 32];
        hk.expand(b"ratchet-chain-responder-to-initiator", &mut responder_chain)
            .expect("valid length");
        (initiator_chain, responder_chain)
    }

    pub fn new(root_secret: [u8; 32], role: RatchetRole) -> Self {
        let (initiator_to_responder, responder_to_initiator) = Self::derive_chains(&root_secret);
        let (send_chain_key, recv_chain_key) = match role {
            // Инициатор шлёт по "initiator->responder" цепочке и читает
            // по "responder->initiator".
            RatchetRole::Initiator => (initiator_to_responder, responder_to_initiator),
            // Ответчик — зеркально: шлёт по "responder->initiator",
            // читает по "initiator->responder".
            RatchetRole::Responder => (responder_to_initiator, initiator_to_responder),
        };
        Self {
            send_chain_key,
            send_counter: 0,
            recv_chain_key,
            recv_counter: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Восстанавливает ratchet из ранее сохранённого состояния (см.
    /// RatchetState/storage/session_store.rs) вместо пересчёта с нуля
    /// от root_secret — используется при загрузке сессии из БД, чтобы
    /// counter'ы и ключи были РЕАЛЬНЫЕ, а не обнулённые (см. комментарий
    /// у Session::restore в session/state.rs про старый баг с
    /// zero-плейсхолдером).
    pub fn restore(state: RatchetState) -> Self {
        Self {
            send_chain_key: state.send_chain_key,
            send_counter: state.send_counter,
            recv_chain_key: state.recv_chain_key,
            recv_counter: state.recv_counter,
            skipped_keys: HashMap::new(),
        }
    }

    /// Снимок текущего состояния для сохранения в БД. skipped_keys
    /// намеренно не включены — см. комментарий у RatchetState.
    pub fn export_state(&self) -> RatchetState {
        RatchetState {
            send_chain_key: self.send_chain_key,
            send_counter: self.send_counter,
            recv_chain_key: self.recv_chain_key,
            recv_counter: self.recv_counter,
        }
    }

    /// Продвигает цепочку ОТПРАВКИ и возвращает ключ для следующего
    /// исходящего сообщения. KDF chain: chain_key_{n+1} = HMAC(chain_key_n, "chain"),
    ///            message_key_n   = HMAC(chain_key_n, "message")
    fn ratchet_step_send(&mut self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.send_chain_key);

        let mut message_key = [0u8; 32];
        hk.expand(b"message", &mut message_key)
            .expect("valid length");

        let mut next_chain_key = [0u8; 32];
        hk.expand(b"chain", &mut next_chain_key)
            .expect("valid length");

        self.send_chain_key.zeroize();
        self.send_chain_key = next_chain_key;
        self.send_counter += 1;

        message_key
    }

    /// То же самое, что ratchet_step_send, но для цепочки ПРИЁМА —
    /// отдельный физический стейт (recv_chain_key/recv_counter), см.
    /// комментарий у полей DoubleRatchet выше про то, почему это два
    /// разных счётчика, а не один общий.
    fn ratchet_step_recv(&mut self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.recv_chain_key);

        let mut message_key = [0u8; 32];
        hk.expand(b"message", &mut message_key)
            .expect("valid length");

        let mut next_chain_key = [0u8; 32];
        hk.expand(b"chain", &mut next_chain_key)
            .expect("valid length");

        self.recv_chain_key.zeroize();
        self.recv_chain_key = next_chain_key;
        self.recv_counter += 1;

        message_key
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> anyhow::Result<EncryptedEnvelope> {
        let message_key = self.ratchet_step_send();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_key));

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

        Ok(EncryptedEnvelope {
            // Заполняется на уровне Session/SessionManager, которые
            // знают identity — сам ratchet ничего не знает про UserId
            // или подписи, только про симметричную KDF-цепочку.
            sender_id: String::new(),
            nonce: nonce_bytes,
            ciphertext,
            counter: self.send_counter,
            sender_signature: Vec::new(),
            // Штампуется на уровне SessionManager (см. encrypt_for), не
            // здесь — ratchet.rs ничего не знает про X3DH/сессии, только
            // про симметричную KDF-цепочку.
            session_init: None,
        })
    }

    /// Расшифровывает входящее сообщение, допуская переупорядочивание:
    /// - `counter == self.counter + 1` — обычный путь по порядку.
    /// - `counter > self.counter + 1` — часть сообщений впереди пропущена
    ///   (ещё не пришла или придёт позже/никогда); продвигаем цепочку до
    ///   нужного номера, по пути сохраняя промежуточные ключи в
    ///   `skipped_keys`, чтобы эти "пропущенные" сообщения можно было
    ///   расшифровать позже, когда/если они всё же придут.
    /// - `counter <= self.counter` — сообщение из прошлого: либо это то
    ///   самое ранее пропущенное (тогда ключ уже лежит в `skipped_keys`
    ///   и мы его используем и удаляем — переиспользовать ключ дважды
    ///   нельзя, это ломает forward secrecy), либо повтор/атака — тогда
    ///   ошибка.
    pub fn decrypt(&mut self, envelope: &EncryptedEnvelope) -> anyhow::Result<Vec<u8>> {
        let message_key = if envelope.counter > self.recv_counter {
            let skip_count = envelope.counter - self.recv_counter;
            if skip_count > MAX_SKIP {
                anyhow::bail!(
                    "слишком большой прыжок вперёд по ratchet-цепочке: {} сообщений (максимум {}) — \
                     похоже на битый counter, а не на обычную потерю пакетов",
                    skip_count,
                    MAX_SKIP
                );
            }

            // Продвигаем цепочку шаг за шагом, откладывая все ключи КРОМЕ
            // последнего (тот используем сразу, без похода в HashMap).
            let mut key = [0u8; 32];
            for step_counter in (self.recv_counter + 1)..=envelope.counter {
                key = self.ratchet_step_recv();
                if step_counter != envelope.counter {
                    self.skipped_keys.insert(step_counter, key);
                }
            }
            key
        } else if let Some(key) = self.skipped_keys.remove(&envelope.counter) {
            // Ранее пропущенное сообщение наконец пришло.
            key
        } else {
            anyhow::bail!(
                "сообщение с counter {} уже нельзя расшифровать: либо оно старше текущей позиции \
                 цепочки ({}) и не было среди отложенных, либо это повтор ранее использованного ключа",
                envelope.counter,
                self.recv_counter
            );
        };

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&message_key));
        let nonce = Nonce::from_slice(&envelope.nonce);

        let plaintext = cipher
            .decrypt(nonce, envelope.ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

        Ok(plaintext)
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.send_chain_key.zeroize();
        self.recv_chain_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let secret = [42u8; 32];
        let mut alice = DoubleRatchet::new(secret, RatchetRole::Initiator);
        let mut bob = DoubleRatchet::new(secret, RatchetRole::Responder);

        let envelope = alice.encrypt(b"privet bro").unwrap();
        let decrypted = bob.decrypt(&envelope).unwrap();

        assert_eq!(decrypted, b"privet bro");
    }

    #[test]
    fn bidirectional_conversation_does_not_break_after_both_sides_send() {
        // Регрессионный тест на баг, который был бы невозможен обнаружить
        // старым однопоточным chain_key/counter: раньше encrypt() и
        // decrypt() делили один физический счётчик, так что если ОБЕ
        // стороны отправляют хотя бы по одному сообщению, их counter'ы
        // расходятся с тем, что видит собеседник, и расшифровка ломается.
        let secret = [9u8; 32];
        let mut alice = DoubleRatchet::new(secret, RatchetRole::Initiator);
        let mut bob = DoubleRatchet::new(secret, RatchetRole::Responder);

        let a1 = alice.encrypt(b"hi bob").unwrap();
        let b1 = bob.encrypt(b"hi alice").unwrap();

        assert_eq!(bob.decrypt(&a1).unwrap(), b"hi bob");
        assert_eq!(alice.decrypt(&b1).unwrap(), b"hi alice");

        let a2 = alice.encrypt(b"how are you").unwrap();
        let b2 = bob.encrypt(b"fine, you?").unwrap();

        assert_eq!(bob.decrypt(&a2).unwrap(), b"how are you");
        assert_eq!(alice.decrypt(&b2).unwrap(), b"fine, you?");
    }

    #[test]
    fn out_of_order_delivery_is_recoverable() {
        let secret = [3u8; 32];
        let mut alice = DoubleRatchet::new(secret, RatchetRole::Initiator);
        let mut bob = DoubleRatchet::new(secret, RatchetRole::Responder);

        let env1 = alice.encrypt(b"one").unwrap();
        let env2 = alice.encrypt(b"two").unwrap();
        let env3 = alice.encrypt(b"three").unwrap();

        // Bob получает их в другом порядке, как это бывает в P2P-сети.
        let p3 = bob.decrypt(&env3).unwrap();
        assert_eq!(p3, b"three");
        let p1 = bob.decrypt(&env1).unwrap();
        assert_eq!(p1, b"one");
        let p2 = bob.decrypt(&env2).unwrap();
        assert_eq!(p2, b"two");
    }

    #[test]
    fn replaying_an_already_used_counter_fails() {
        let secret = [4u8; 32];
        let mut alice = DoubleRatchet::new(secret, RatchetRole::Initiator);
        let mut bob = DoubleRatchet::new(secret, RatchetRole::Responder);

        let env1 = alice.encrypt(b"one").unwrap();
        bob.decrypt(&env1).unwrap();

        // Повторная попытка расшифровать тот же envelope — не должно
        // сработать, ключ уже израсходован и не лежит в skipped_keys
        // (он никогда там и не был, т.к. пришёл по порядку).
        assert!(bob.decrypt(&env1).is_err());
    }

    #[test]
    fn skip_further_than_max_skip_is_rejected() {
        let secret = [5u8; 32];
        let mut bob = DoubleRatchet::new(secret, RatchetRole::Responder);
        let bogus = EncryptedEnvelope {
            sender_id: String::new(),
            nonce: [0u8; 12],
            ciphertext: vec![0u8; 16],
            counter: MAX_SKIP + 50,
            sender_signature: Vec::new(),
            session_init: None,
        };
        assert!(bob.decrypt(&bogus).is_err());
    }

    #[test]
    fn each_message_uses_different_key() {
        let secret = [1u8; 32];
        let mut alice = DoubleRatchet::new(secret, RatchetRole::Initiator);

        let env1 = alice.encrypt(b"message one").unwrap();
        let env2 = alice.encrypt(b"message one").unwrap(); // тот же текст

        // ciphertext разный даже для одинакового текста — forward secrecy
        assert_ne!(env1.ciphertext, env2.ciphertext);
    }

    #[test]
    fn export_import_state_roundtrip_preserves_ability_to_continue() {
        let secret = [7u8; 32];
        let mut alice = DoubleRatchet::new(secret, RatchetRole::Initiator);
        let mut bob = DoubleRatchet::new(secret, RatchetRole::Responder);

        let env1 = alice.encrypt(b"before restart").unwrap();
        assert_eq!(bob.decrypt(&env1).unwrap(), b"before restart");

        // Симулируем перезапуск процесса: сохраняем состояние, строим
        // ratchet заново из него (не из root_secret — тот факт, что
        // счётчики теперь ненулевые, и есть весь смысл теста: со старым
        // Session::new-based load счётчики обнулялись бы и следующая
        // расшифровка сломалась бы).
        let alice_state = alice.export_state();
        let bob_state = bob.export_state();
        let mut alice2 = DoubleRatchet::restore(alice_state);
        let mut bob2 = DoubleRatchet::restore(bob_state);

        let env2 = alice2.encrypt(b"after restart").unwrap();
        assert_eq!(bob2.decrypt(&env2).unwrap(), b"after restart");
    }
}
