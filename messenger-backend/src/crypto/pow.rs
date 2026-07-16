//! Proof of Work: отправитель должен найти nonce такой, что
//! SHA256(challenge || nonce) начинается с N нулевых бит.
//! Используется для (1) первого сообщения незнакомцу, (2) публикации
//! записи в DHT. ~100мс на обычном телефоне, ощутимо дороже при спаме
//! на миллионы сообщений/записей.

use rand::RngCore;
use sha2::{Digest, Sha256};

/// Сложность в битах. 20 бит ≈ 100-300мс на среднем мобильном CPU.
pub const DEFAULT_DIFFICULTY_BITS: u32 = 20;

pub struct PowChallenge {
    pub challenge: [u8; 32],
    pub difficulty_bits: u32,
}

pub struct PowSolution {
    pub nonce: u64,
}

impl PowChallenge {
    pub fn new(difficulty_bits: u32) -> Self {
        let mut challenge = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        Self {
            challenge,
            difficulty_bits,
        }
    }

    /// Детерминированный вариант `new` — challenge получается хэшем
    /// `seed`, а не случайным. Нужен там, где верификатор должен
    /// пересчитать РОВНО ТОТ ЖЕ challenge, что использовал издатель при
    /// решении PoW (например DhtRecordBuilder::verify пересчитывает его
    /// из тех же signable-байт записи, что подписаны). Со случайным
    /// `new()` это было бы невозможно — верификатор не знает исходный
    /// challenge издателя, только nonce. Домен-разделитель в хэше не
    /// даёт "случайно" получить тот же challenge для другого назначения
    /// PoW (например DhtRecord vs PreKeyBundleRecord), даже если seed
    /// байты совпадут.
    pub fn derive_from(domain: &str, seed: &[u8], difficulty_bits: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update(seed);
        let digest = hasher.finalize();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&digest);
        Self {
            challenge,
            difficulty_bits,
        }
    }

    /// Брутфорсит nonce. Блокирующая операция — вызывать в отдельном
    /// потоке/spawn_blocking, не в async-контексте напрямую.
    pub fn solve(&self) -> PowSolution {
        let mut nonce: u64 = 0;
        loop {
            if self.check(nonce) {
                return PowSolution { nonce };
            }
            nonce += 1;
        }
    }

    pub fn check(&self, nonce: u64) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.challenge);
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();
        leading_zero_bits(&hash) >= self.difficulty_bits
    }

    pub fn verify(&self, solution: &PowSolution) -> bool {
        self.check(solution.nonce)
    }
}

fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_and_verify() {
        // низкая сложность для быстрого теста
        let challenge = PowChallenge::new(12);
        let solution = challenge.solve();
        assert!(challenge.verify(&solution));
    }

    #[test]
    fn wrong_nonce_fails() {
        let challenge = PowChallenge::new(20);
        let bad = PowSolution { nonce: 0 };
        // почти наверняка не пройдёт со сложностью 20 бит
        assert!(!challenge.verify(&bad) || challenge.check(0));
    }
}
