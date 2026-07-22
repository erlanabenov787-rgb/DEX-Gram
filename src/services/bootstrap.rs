//! Реализация того, что было только ЗАДОКУМЕНТИРОВАНО в
//! `config/settings.rs` (см. комментарий у `Config::bootstrap_url`), но
//! нигде не было реально написано:
//!
//!   "Если задан через env BOOTSTRAP_URL — нода при старте делает
//!    GET {bootstrap_url}/relays и применяет список relay без участия
//!    пользователя."
//!
//! ЭТО И ЕСТЬ ПРИЧИНА, ПОЧЕМУ СООБЩЕНИЯ НЕ ДОХОДИЛИ:
//! `RelayRegistry::new()` в main.rs создаёт ПУСТОЙ реестр. Единственный
//! способ его заполнить — `NodeCommand::UpdateRelays` (см.
//! network/p2p.rs::handle_command). Все остальные места в проекте
//! (services/background.rs, services/sync.rs) только ЧИТАЮТ из реестра
//! и ждут, пока кто-нибудь пришлёт `UpdateRelays` — но никто в проекте
//! его не отправлял. Поэтому `RelayScoring::select_hops()` в
//! dispatcher::send_message всегда получал 0 известных relay и падал с
//! `OnionChainTooShort` ДО того, как пакет вообще пытался уйти в сеть —
//! то есть сообщение не доходило даже до первого relay, что в точности
//! совпадает с симптомом "отправляется, но нихуя не приходит и не
//! приходит на релеи".
//!
//! Этот файл не меняет отправку сообщений — он только подключает уже
//! существующий `NodeCommand::UpdateRelays` к реальному источнику данных.

use std::time::Duration;

use serde::Deserialize;
use tokio::sync::mpsc::UnboundedSender;

use crate::network::relay::RelayEntry;
use crate::network::NodeCommand;

/// Реальный формат ответа bootstrap-server (проверено вживую через
/// `curl http://127.0.0.1:8080/relays`):
/// `{"relays":[{"peer_id":"...","multiaddr":"...","onion_public_key":"..."}]}`
///
/// ВАЖНО: это НЕ то же самое, что `config::RelayInfo` (там поля
/// `relay_id`/`address`/`onion_public_key_hex` — они используются
/// где-то ещё в проекте, возможно, для статического конфига). Здесь
/// отдельная структура именно под wire-формат bootstrap-server, чтобы
/// не путать два разных JSON-контракта.
#[derive(Debug, Deserialize)]
struct BootstrapRelayEntry {
    peer_id: String,
    multiaddr: String,
    onion_public_key: String,
}

#[derive(Debug, Deserialize)]
struct RelaysResponse {
    relays: Vec<BootstrapRelayEntry>,
}

/// Делает `GET {bootstrap_url}/relays`, парсит ответ и применяет список
/// через уже существующий `NodeCommand::UpdateRelays`. Возвращает
/// количество применённых relay.
pub async fn fetch_and_apply_relays(
    bootstrap_url: &str,
    cmd_tx: &UnboundedSender<NodeCommand>,
) -> anyhow::Result<usize> {
    let url = format!("{}/relays", bootstrap_url.trim_end_matches('/'));
    tracing::info!("Bootstrap: запрашиваю список relay у {url}");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let resp = client.get(&url).send().await?.error_for_status()?;
    let body = resp.text().await?;

    let parsed: RelaysResponse = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!("не удалось распарсить ответ bootstrap {url}: {e}. Тело ответа: {body}")
    })?;

    let mut entries = Vec::with_capacity(parsed.relays.len());
    for info in parsed.relays {
        match RelayEntry::from_hex_key(info.peer_id.clone(), info.multiaddr.clone(), &info.onion_public_key) {
            Some(entry) => entries.push(entry),
            None => tracing::warn!(
                "Bootstrap: relay {} пришёл с невалидным onion_public_key (нужно 64 hex-символа = 32 байта), пропускаю",
                info.peer_id
            ),
        }
    }

    let count = entries.len();
    if count == 0 {
        anyhow::bail!("bootstrap {url} вернул 0 валидных relay (пусто или все записи невалидны)");
    }

    cmd_tx
        .send(NodeCommand::UpdateRelays { relays: entries })
        .map_err(|_| anyhow::anyhow!("NodeCommand канал уже закрыт, не могу применить relay"))?;

    Ok(count)
}

/// Спавнит фоновую задачу, которая получает relay от bootstrap_url с
/// несколькими повторами (сервер друга может ещё не быть поднят в
/// момент нашего старта) и применяет их через `UpdateRelays`.
///
/// Вызывать из main.rs сразу после того, как `cmd_tx` создан — работает
/// параллельно с `node.run_with_commands(cmd_rx)`, ничего в event loop-е
/// не меняет.
pub fn spawn_bootstrap_fetch(bootstrap_url: String, cmd_tx: UnboundedSender<NodeCommand>) {
    tokio::spawn(async move {
        const MAX_ATTEMPTS: u32 = 5;
        for attempt in 1..=MAX_ATTEMPTS {
            match fetch_and_apply_relays(&bootstrap_url, &cmd_tx).await {
                Ok(count) => {
                    tracing::info!("Bootstrap: получено и применено {count} relay из {bootstrap_url}");
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        "Bootstrap: попытка {attempt}/{MAX_ATTEMPTS} получить relay с {bootstrap_url} не удалась: {e}"
                    );
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(Duration::from_secs(3 * attempt as u64)).await;
                    }
                }
            }
        }
        tracing::error!(
            "Bootstrap: не удалось получить relay после {MAX_ATTEMPTS} попыток с {bootstrap_url} — \
             send будет падать с 'OnionChainTooShort', пока relay не появятся (проверь что \
             bootstrap-сервер доступен и BOOTSTRAP_URL указывает на него правильно, включая /relays)"
        );
    });
}
