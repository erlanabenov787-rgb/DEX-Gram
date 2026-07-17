//! DEX-Gram Bootstrap Server
//!
//! Лёгкий HTTP-сервер на axum. Хранит список известных relay-узлов
//! и отдаёт его клиентским нодам по GET /relays.
//!
//! # Запуск
//!
//! ```sh
//! RELAY_LIST='[{"peer_id":"12D3...","multiaddr":"/ip4/1.2.3.4/tcp/9001","onion_public_key":"aabb..."}]' \
//!   BOOTSTRAP_PORT=8080 \
//!   ./bootstrap-server
//! ```
//!
//! # Типичная схема развёртывания
//!
//! На одном хосте запускаются два процесса:
//! 1. `messenger-backend` с IS_RELAY=true — обычный relay-нод.
//!    После старта выводит свой onion_public_key в лог.
//! 2. `bootstrap-server` с RELAY_LIST, где прописан адрес этого relay.
//!
//! Клиентское приложение (messenger-backend в Tauri) один раз
//! получает от пользователя URL bootstrap-сервера, сохраняет в БД
//! и при каждом следующем запуске само подтягивает список relay.

use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

/// Информация об одном relay-узле (сериализуется в JSON для клиентов).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    /// libp2p PeerId строкой.
    pub peer_id: String,
    /// Multiaddr для подключения (например "/ip4/1.2.3.4/tcp/9001").
    pub multiaddr: String,
    /// X25519 onion-публичный ключ, hex, 64 символа = 32 байта.
    /// Берётся из лога messenger-backend при первом старте с IS_RELAY=true.
    pub onion_public_key: String,
}

#[derive(Debug, Clone, Serialize)]
struct RelaysResponse {
    relays: Vec<RelayInfo>,
}

struct AppState {
    relays: Vec<RelayInfo>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "bootstrap_server=info".to_string()),
        )
        .init();

    // ── Конфигурация через env ──────────────────────────────────────────────
    //
    // RELAY_LIST — JSON-массив объектов RelayInfo.
    // Пример:
    //   RELAY_LIST='[{"peer_id":"12D3...","multiaddr":"/ip4/1.2.3.4/tcp/9001","onion_public_key":"aabb..."}]'
    //
    // RELAY_LIST_FILE — альтернативно: путь к JSON-файлу с тем же содержимым.
    // (Удобно в docker-compose: mount конфиг как файл.)
    //
    // BOOTSTRAP_PORT — порт, на котором слушать (по умолчанию 8080).

    let relay_json = if let Ok(path) = std::env::var("RELAY_LIST_FILE") {
        std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("Не могу прочитать RELAY_LIST_FILE={path}: {e}"))?
    } else {
        std::env::var("RELAY_LIST").unwrap_or_else(|_| "[]".to_string())
    };

    let relays: Vec<RelayInfo> = serde_json::from_str(&relay_json).map_err(|e| {
        anyhow::anyhow!("Не могу распарсить RELAY_LIST как JSON-массив RelayInfo: {e}")
    })?;

    let port: u16 = std::env::var("BOOTSTRAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    tracing::info!(
        "Bootstrap-сервер стартует на 0.0.0.0:{port} — {} relay(s) в списке",
        relays.len()
    );

    for r in &relays {
        tracing::info!(
            "  relay: peer_id={} addr={}",
            &r.peer_id,
            &r.multiaddr
        );
    }

    if relays.is_empty() {
        tracing::warn!(
            "RELAY_LIST пуст — клиенты получат пустой список и не смогут подключиться. \
             Задайте RELAY_LIST или RELAY_LIST_FILE."
        );
    }

    let state = Arc::new(AppState { relays });

    // CORS: разрешаем любые origin — сервер публичный, авторизация не нужна.
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    let app = Router::new()
        .route("/relays", get(handle_get_relays))
        .route("/health", get(handle_health))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    tracing::info!("Слушаем на {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    Ok(())
}

/// GET /relays — основной эндпоинт, который опрашивают клиентские ноды.
///
/// Возвращает JSON:
/// ```json
/// { "relays": [ { "peer_id": "...", "multiaddr": "...", "onion_public_key": "..." } ] }
/// ```
async fn handle_get_relays(State(state): State<Arc<AppState>>) -> Json<RelaysResponse> {
    tracing::debug!("GET /relays — {} relay(s)", state.relays.len());
    Json(RelaysResponse {
        relays: state.relays.clone(),
    })
}

/// GET /health — liveness check для reverse-proxy / systemd / docker healthcheck.
async fn handle_health() -> &'static str {
    "ok"
}
