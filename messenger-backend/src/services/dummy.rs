//! Вспомогательные утилиты для dummy traffic.
//!
//! Реальная отправка dummy-пакетов вынесена в
//! `network::dispatcher::send_dummy_packet` (вызывается через
//! `NodeCommand::SendDummy` из `services::background`). Этот модуль
//! содержит только чистые функции, которые можно тестировать без
//! tokio runtime и без доступа к NodeHandle.

/// Возвращает случайный интервал ожидания в секундах в диапазоне [min, max).
/// Используется в background.rs для рандомизации dummy-трафика —
/// постоянный интервал был бы легко отличим от реального трафика.
pub fn random_interval_secs(min: u64, max: u64) -> u64 {
    if max > min {
        rand::random::<u64>() % (max - min) + min
    } else {
        min
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_in_range() {
        for _ in 0..200 {
            let v = random_interval_secs(5, 15);
            assert!(v >= 5 && v < 15, "interval {v} out of [5, 15)");
        }
    }

    #[test]
    fn interval_degenerate() {
        // min == max → всегда возвращаем min
        assert_eq!(random_interval_secs(10, 10), 10);
        // min > max → возвращаем min (защита от инвертированного диапазона)
        assert_eq!(random_interval_secs(20, 5), 20);
    }
}
