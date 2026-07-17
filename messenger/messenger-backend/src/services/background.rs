//! Background задачи: dummy traffic, republish DHT, mailbox fetch, cleanup mailbox, etc.
//!
//! Все задачи общаются с NodeHandle через `cmd_tx: UnboundedSender<NodeCommand>` —
//! NodeHandle к этому моменту уже передан внутрь `run_with_commands(cmd_rx)`, и
//! единственный способ достучаться до него снаружи — через этот канал.
//!
//! Задачи читают список relay из `Arc<RelayRegistry>` на каждой итерации —
//! поэтому когда bootstrap вернёт список relay (NodeCommand::UpdateRelays),
//! они автоматически подхватят новые relay без перезапуска.

use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::network::relay::RelayRegistry;
use crate::network::NodeCommand;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::sleep;

/// Интервал между периодическими MAILBOX_FETCH-запросами к каждому relay.
const MAILBOX_FETCH_INTERVAL_SECS: u64 = 30;

/// Запускает все фоновые задачи нода.
///
/// Принимает `cmd_tx` вместо `&mut NodeHandle` — к этому моменту NodeHandle
/// уже передан в `node.run_with_commands(cmd_rx)` (main.rs / lib.rs).
///
/// Принимает `Arc<RelayRegistry>` — список relay читается динамически
/// на каждой итерации, поэтому задачи начнут работать сразу после того
/// как bootstrap вернёт список relay.
pub fn run_background_tasks(
    cmd_tx: UnboundedSender<NodeCommand>,
    cfg: &Config,
    registry: Arc<RelayRegistry>,
) {
    let min = cfg.dummy_traffic_interval_secs_min;
    let max = cfg.dummy_traffic_interval_secs_max;

    // ── Задача 1: dummy traffic ──────────────────────────────────────────────
    // Реально отправляет DummyTraffic-пакет на случайный relay через
    // NodeCommand::SendDummy → dispatcher::send_dummy_packet.
    // Список relay читается при каждом срабатывании из RelayRegistry —
    // задача запускается сразу, но начнёт слать пакеты как только
    // bootstrap вернёт relay.
    {
        let reg = registry.clone();
        let tx = cmd_tx.clone();
        tokio::spawn(async move {
            loop {
                let interval = if max > min {
                    rand::random::<u64>() % (max - min) + min
                } else {
                    min
                };
                sleep(Duration::from_secs(interval)).await;

                let ids = reg.relay_ids();
                if ids.is_empty() {
                    tracing::trace!(
                        "Dummy traffic: реестр relay пуст (bootstrap ещё не ответил), пропуск"
                    );
                    continue;
                }

                // Случайный relay из текущего реестра
                let idx = rand::random::<usize>() % ids.len();
                let relay_id = ids[idx].clone();

                if tx.send(NodeCommand::SendDummy { relay_id: relay_id.clone() }).is_err() {
                    tracing::info!(
                        "NodeCommand канал закрыт, останавливаем dummy-traffic задачу"
                    );
                    return;
                }
                tracing::trace!("Dummy трафик запланирован на relay {relay_id}");
            }
        });
    }

    // ── Задача 2: периодический MAILBOX_FETCH ────────────────────────────────
    // Каждые MAILBOX_FETCH_INTERVAL_SECS опрашиваем каждый known relay за нашими
    // оффлайн-сообщениями. Список relay читается из RelayRegistry на каждой
    // итерации — автоматически подхватывает новые relay от bootstrap.
    {
        let reg = registry.clone();
        let tx = cmd_tx.clone();
        tokio::spawn(async move {
            // Небольшая начальная задержка — даём ноду поднять соединения
            sleep(Duration::from_secs(5)).await;
            loop {
                let ids = reg.relay_ids();
                if ids.is_empty() {
                    tracing::debug!(
                        "Периодический MAILBOX_FETCH: реестр relay пуст, ждём следующего цикла"
                    );
                } else {
                    for relay_id in &ids {
                        let (respond_to, _rx) = tokio::sync::oneshot::channel();
                        if tx
                            .send(NodeCommand::FetchMailbox {
                                relay_id: relay_id.clone(),
                                respond_to,
                            })
                            .is_err()
                        {
                            tracing::info!(
                                "NodeCommand канал закрыт, останавливаем mailbox-fetch фоновую задачу"
                            );
                            return;
                        }
                        tracing::debug!("Периодический MAILBOX_FETCH → relay {relay_id}");
                    }
                }
                sleep(Duration::from_secs(MAILBOX_FETCH_INTERVAL_SECS)).await;
            }
        });
    }

    // ── Задача 3: периодический DHT republish ────────────────────────────────
    // DhtRecord и PreKeyBundle имеют TTL = DHT_RECORD_TTL_SECS (24ч).
    // Переопубликуем каждые DHT_REPUBLISH_INTERVAL_SECS (6ч) чтобы запись
    // не вымывалась из Kademlia пока нод живёт.
    {
        let tx = cmd_tx.clone();
        tokio::spawn(async move {
            // Первый republish после старта — ждём до следующего окна
            sleep(Duration::from_secs(crate::constants::DHT_REPUBLISH_INTERVAL_SECS)).await;
            loop {
                if tx.send(NodeCommand::RepublishDht).is_err() {
                    tracing::info!(
                        "NodeCommand канал закрыт, останавливаем DHT-republish задачу"
                    );
                    return;
                }
                tracing::info!("NodeCommand::RepublishDht отправлен (периодическая переопубликовка)");
                sleep(Duration::from_secs(crate::constants::DHT_REPUBLISH_INTERVAL_SECS)).await;
            }
        });
    }

    tracing::info!(
        "Background tasks started: dummy traffic (interval {}-{}s), \
         mailbox fetch (every {}s, relay из RelayRegistry), \
         DHT republish (every {}s)",
        min,
        max,
        MAILBOX_FETCH_INTERVAL_SECS,
        crate::constants::DHT_REPUBLISH_INTERVAL_SECS,
    );
}
