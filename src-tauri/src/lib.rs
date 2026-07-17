use std::sync::Arc;

use messenger_backend::config::Config;
use messenger_backend::identity::Identity;
use messenger_backend::network::{self, NodeCommand, NodeHandle};
use messenger_backend::network::relay::registry::RelayEntry;
use messenger_backend::network::relay::RelayRegistry;
use messenger_backend::session::manager::PeerIdentitySource;
use messenger_backend::storage::db::DbPeerIdentitySource;
use messenger_backend::storage::Database;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot, Mutex};
use x25519_dalek::{PublicKey, StaticSecret};

/// Держим Database за Arc<Mutex<..>> — не std::sync::Mutex, т.к. commands
/// теперь async (send_message ждёт ответа от node loop через oneshot) и
/// не должны держать std-мьютекс через await point.
struct AppState {
    db: Arc<Mutex<Database>>,
    me: Arc<Identity>,
    /// Канал в задачу, которая владеет `NodeHandle` (см. run_with_commands
    /// в network::p2p) — единственный способ попросить нод отправить
    /// сообщение, раз сам NodeHandle заперт внутри отдельного tokio-таска.
    node_commands: mpsc::UnboundedSender<NodeCommand>,
}

#[derive(Serialize)]
struct MeInfo {
    user_id: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct Contact {
    user_id: String,
    display_name: String,
}

#[derive(Serialize)]
struct Message {
    direction: String, // "sent" | "received"
    text: String,
    sent_at: i64,
}

/// Пейлоад события "message-received", которое фронтенд слушает через
/// window.__TAURI__.event.listen, чтобы обновить экран без опроса.
#[derive(Serialize, Clone)]
struct IncomingMessageEvent {
    from_user_id: String,
    text: String,
}

/// Данные одного relay-узла, полученные от bootstrap.
/// Фронтенд вызывает `update_relays` с этим списком после подключения к bootstrap.
#[derive(Deserialize)]
struct RelayInfoDto {
    peer_id: String,
    multiaddr: String,
    onion_public_key: String, // hex, 64 символа = 32 байта
}

fn db_path(app: &tauri::AppHandle) -> String {
    let dir = app
        .path()
        .app_data_dir()
        .expect("не удалось получить app data dir от Tauri");
    std::fs::create_dir_all(&dir).expect("не удалось создать app data dir");
    dir.join("messenger.db").to_string_lossy().into_owned()
}

#[tauri::command]
fn get_me(state: State<AppState>) -> MeInfo {
    MeInfo {
        user_id: state.me.user_id.clone(),
        public_key_hex: hex::encode(state.me.verifying_key.as_bytes()),
    }
}

#[tauri::command]
async fn list_contacts(state: State<'_, AppState>) -> Result<Vec<Contact>, String> {
    let db = state.db.lock().await;
    db.list_contacts()
        .map(|rows| {
            rows.into_iter()
                .map(|(user_id, display_name)| Contact {
                    user_id,
                    display_name,
                })
                .collect()
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_contact(
    state: State<'_, AppState>,
    user_id: String,
    display_name: String,
    public_key_hex: String,
) -> Result<(), String> {
    let pubkey = hex::decode(&public_key_hex).map_err(|e| e.to_string())?;
    let db = state.db.lock().await;
    db.add_contact(&user_id, &display_name, &pubkey)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_history(
    state: State<'_, AppState>,
    contact_user_id: String,
    limit: u32,
) -> Result<Vec<Message>, String> {
    let db = state.db.lock().await;
    db.get_history(&contact_user_id, limit)
        .map(|rows| {
            let mut msgs: Vec<Message> = rows
                .into_iter()
                .map(|(direction, text, sent_at)| Message {
                    direction,
                    text,
                    sent_at,
                })
                .collect();
            msgs.sort_by_key(|m| m.sent_at);
            msgs
        })
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_message(
    state: State<'_, AppState>,
    contact_user_id: String,
    text: String,
) -> Result<(), String> {
    {
        let db = state.db.lock().await;
        db.save_message(&contact_user_id, "sent", &text)
            .map_err(|e| e.to_string())?;
    }

    let (resp_tx, resp_rx) = oneshot::channel();
    state
        .node_commands
        .send(NodeCommand::SendText {
            to: contact_user_id.clone(),
            text: text.into_bytes(),
            respond_to: resp_tx,
        })
        .map_err(|_| "network node не запущен".to_string())?;

    resp_rx
        .await
        .map_err(|_| "node не ответил на запрос отправки".to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_my_card(state: State<AppState>) -> String {
    serde_json::json!({
        "user_id": state.me.user_id,
        "public_key_hex": hex::encode(state.me.verifying_key.as_bytes()),
    })
    .to_string()
}

#[tauri::command]
async fn lookup_user(
    state: State<'_, AppState>,
    user_id: String,
) -> Result<serde_json::Value, String> {
    let (resp_tx, resp_rx) = oneshot::channel();
    state
        .node_commands
        .send(NodeCommand::LookupUser {
            user_id: user_id.clone(),
            respond_to: resp_tx,
        })
        .map_err(|_| "network node не запущен".to_string())?;

    let record = resp_rx
        .await
        .map_err(|_| "node не ответил на lookup".to_string())?
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "user_id": record.user_id,
        "public_key_hex": hex::encode(&record.public_key),
    }))
}

/// Передаёт список relay-узлов, полученных от bootstrap, в network node.
///
/// Используется внутренне при авто-fetch от bootstrap.
/// Фронтенд вызывает эту команду только в редких случаях (ручной override).
async fn apply_relays_internal(
    relays: Vec<RelayInfoDto>,
    node_commands: &mpsc::UnboundedSender<NodeCommand>,
) -> Result<(), String> {
    let entries: Vec<RelayEntry> = relays
        .into_iter()
        .filter_map(|dto| {
            match RelayEntry::from_hex_key(dto.peer_id.clone(), dto.multiaddr, &dto.onion_public_key) {
                Some(entry) => Some(entry),
                None => {
                    tracing::warn!(
                        "update_relays: невалидный onion_public_key для relay {}",
                        dto.peer_id
                    );
                    None
                }
            }
        })
        .collect();

    if entries.is_empty() {
        return Err("Список relay пуст или содержит только невалидные записи".to_string());
    }

    node_commands
        .send(NodeCommand::UpdateRelays { relays: entries })
        .map_err(|_| "network node не запущен".to_string())?;

    Ok(())
}

/// GET {url}/relays → парсит JSON → отправляет NodeCommand::UpdateRelays.
///
/// Не блокирует запуск ноды: вызывается в фоновом таске с retry+backoff.
async fn fetch_relays_from_bootstrap(
    bootstrap_url: &str,
    node_commands: &mpsc::UnboundedSender<NodeCommand>,
) -> Result<(), String> {
    let relays_url = format!(
        "{}/relays",
        bootstrap_url.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("reqwest build: {e}"))?;

    let resp = client
        .get(&relays_url)
        .send()
        .await
        .map_err(|e| format!("GET {relays_url}: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "Bootstrap ответил {}: {}",
            resp.status(),
            relays_url
        ));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Не JSON от bootstrap: {e}"))?;

    // Принимаем как { "relays": [...] }, так и просто [...]
    let arr = if let Some(arr) = json.get("relays").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = json.as_array() {
        arr.clone()
    } else {
        return Err("Bootstrap вернул не массив relay и не объект с полем 'relays'".to_string());
    };

    let dtos: Vec<RelayInfoDto> = arr
        .into_iter()
        .filter_map(|item| {
            let peer_id = item.get("peer_id")?.as_str()?.to_string();
            let multiaddr = item.get("multiaddr")?.as_str()?.to_string();
            let onion_public_key = item.get("onion_public_key")?.as_str()?.to_string();
            Some(RelayInfoDto { peer_id, multiaddr, onion_public_key })
        })
        .collect();

    if dtos.is_empty() {
        return Err("Bootstrap вернул пустой или невалидный список relay".to_string());
    }

    apply_relays_internal(dtos, node_commands).await
}

/// Фоновый таск: пытается получить relay от bootstrap с exponential backoff.
/// Не блокирует запуск приложения — делается в отдельном tokio-spawn.
fn spawn_bootstrap_fetch(
    bootstrap_url: String,
    node_commands: mpsc::UnboundedSender<NodeCommand>,
) {
    tauri::async_runtime::spawn(async move {
        let mut delay = std::time::Duration::from_secs(3);
        for attempt in 1u32..=8 {
            tracing::info!(
                "Авто-fetch relay от bootstrap (попытка {}/8): {}",
                attempt,
                bootstrap_url
            );
            match fetch_relays_from_bootstrap(&bootstrap_url, &node_commands).await {
                Ok(()) => {
                    tracing::info!("Relay от bootstrap получены успешно");
                    return;
                }
                Err(e) => {
                    tracing::warn!("Bootstrap fetch попытка {attempt} провалилась: {e}");
                    if attempt < 8 {
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(std::time::Duration::from_secs(120));
                    }
                }
            }
        }
        tracing::error!(
            "Bootstrap недоступен после 8 попыток: {}. Пользователь может ввести URL вручную в Settings.",
            bootstrap_url
        );
    });
}

/// Сохраняет URL bootstrap-сервера в локальной БД и немедленно подтягивает
/// список relay.
///
/// Фронтенд вызывает эту команду когда пользователь вводит адрес сервера
/// в Settings. После этого URL сохраняется навсегда — при каждом следующем
/// запуске приложение само подключается без участия пользователя.
#[tauri::command]
async fn set_bootstrap_url(
    state: State<'_, AppState>,
    url: String,
) -> Result<(), String> {
    let url = url.trim().to_string();
    if url.is_empty() {
        return Err("URL не может быть пустым".to_string());
    }

    // Базовая валидация — должно быть http:// или https://
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("URL должен начинаться с http:// или https://".to_string());
    }

    // Сохраняем в БД
    {
        let db = state.db.lock().await;
        db.set_setting("bootstrap_url", &url)
            .map_err(|e| format!("Ошибка сохранения URL: {e}"))?;
    }

    // Немедленно пробуем получить relay
    fetch_relays_from_bootstrap(&url, &state.node_commands).await
}

/// Возвращает сохранённый URL bootstrap-сервера (или null если не задан).
#[tauri::command]
async fn get_bootstrap_url(
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let db = state.db.lock().await;
    db.get_setting("bootstrap_url").map_err(|e| e.to_string())
}

/// Удаляет сохранённый URL bootstrap-сервера (сброс).
#[tauri::command]
async fn clear_bootstrap_url(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let db = state.db.lock().await;
    db.delete_setting("bootstrap_url").map_err(|e| e.to_string())
}

/// Передаёт список relay вручную (legacy / override).
/// Оставлено для совместимости и продвинутых пользователей.
#[tauri::command]
async fn update_relays(
    state: State<'_, AppState>,
    relays: Vec<RelayInfoDto>,
) -> Result<(), String> {
    apply_relays_internal(relays, &state.node_commands).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(move |app| {
            let app_handle = app.handle().clone();

            let path = db_path(&app_handle);
            let db = Database::open(&path).expect("failed to open local db");

            let me = match db.load_identity().expect("failed to read identity") {
                Some((secret_bytes, saved_user_id)) => {
                    let identity = Identity::from_secret_bytes(
    secret_bytes.try_into().expect("secret must be 32 bytes")
);
                    debug_assert_eq!(identity.user_id, saved_user_id);
                    identity
                }
                None => {
                    let identity = Identity::generate();
                    db.save_identity(&identity.export_secret_bytes(), &identity.user_id)
                        .expect("failed to save identity");
                    identity
                }
            };

            let (x3dh_identity, signed_prekey) = match db.load_x3dh_keys().expect("failed to read x3dh keys") {
                Some((identity_bytes, prekey_bytes)) => {
                    (StaticSecret::from(identity_bytes), StaticSecret::from(prekey_bytes))
                }
                None => {
                    let identity_secret = network::dht::generate_signed_prekey();
                    let prekey_secret = network::dht::generate_signed_prekey();
                    db.save_x3dh_keys(&identity_secret.to_bytes(), &prekey_secret.to_bytes())
                        .expect("failed to save x3dh keys");
                    (identity_secret, prekey_secret)
                }
            };
            let x3dh_identity_public = PublicKey::from(&x3dh_identity);
            let signed_prekey_public = PublicKey::from(&signed_prekey);
            let one_time_prekeys = network::dht::generate_one_time_prekeys(
                messenger_backend::constants::PREKEY_BATCH_SIZE,
            );
            let one_time_prekey_publics: Vec<PublicKey> =
                one_time_prekeys.iter().map(PublicKey::from).collect();

            let onion_secret = match db.load_onion_key().expect("failed to read onion key") {
                Some(bytes) => StaticSecret::from(bytes),
                None => {
                    let secret = network::dht::generate_signed_prekey();
                    db.save_onion_key(&secret.to_bytes())
                        .expect("failed to save onion key");
                    secret
                }
            };
            let onion_public = PublicKey::from(&onion_secret);
            tracing::info!(
                "Onion public key (если узел relay): {}",
                hex::encode(onion_public.as_bytes())
            );

            // Читаем сохранённый bootstrap_url ДО того как база уходит в Arc<Mutex>
            let saved_bootstrap_url = db.get_setting("bootstrap_url")
                .ok()
                .flatten();

            let db = Arc::new(Mutex::new(db));

            let cfg = {
                #[cfg(target_os = "android")]
                {
                    let files_dir = app_handle
                        .path()
                        .app_data_dir()
                        .expect("failed to get app data dir")
                        .to_string_lossy()
                        .into_owned();
                    Config::from_env().with_android_paths(&files_dir)
                }
                #[cfg(not(target_os = "android"))]
                {
                    Config::from_env()
                }
            };

            let me = Arc::new(me);

            let identity_db_path = path.clone();
            let identity_source: Arc<dyn PeerIdentitySource> = Arc::new(
                DbPeerIdentitySource::new(
                    Database::open(&identity_db_path).expect("failed to open identity db"),
                ),
            );

            let relay_registry = RelayRegistry::new();

            let (node_cmd_tx, node_cmd_rx) =
                mpsc::unbounded_channel::<NodeCommand>();

            app.manage(AppState {
                db: db.clone(),
                me: me.clone(),
                node_commands: node_cmd_tx.clone(),
            });

            let node_cmd_tx_tasks = node_cmd_tx.clone();
            let registry_for_tasks = relay_registry.clone();

            let db_for_incoming = db.clone();

            // Если bootstrap_url уже сохранён в БД — запускаем авто-fetch
            // до инициализации ноды, чтобы relay были готовы сразу.
            // Если BOOTSTRAP_URL задан в env — приоритет у него.
            let effective_bootstrap_url = cfg.bootstrap_url.clone().or(saved_bootstrap_url);

            if let Some(ref url) = effective_bootstrap_url {
                tracing::info!("Сохранённый bootstrap URL найден, запускаем авто-fetch: {url}");
                spawn_bootstrap_fetch(url.clone(), node_cmd_tx.clone());
            }

            tauri::async_runtime::spawn(async move {
                let identity_source_clone: Arc<dyn PeerIdentitySource> = identity_source;

                let (mut node, mut incoming_rx) = NodeHandle::start(
                    &cfg,
                    me.clone(),
                    identity_source_clone,
                    x3dh_identity,
                    signed_prekey,
                    one_time_prekeys,
                    onion_secret,
                    relay_registry,
                )
                .await
                .expect("failed to start libp2p node");

                tracing::info!("libp2p нод поднят: {}", node.local_peer_id);

                // Публикуем DHT-запись с пустыми mailbox_candidates —
                // relay придут от bootstrap через NodeCommand::UpdateRelays
                // (см. spawn_bootstrap_fetch выше), после чего фоновые задачи
                // и RepublishDht обновят запись с заполненными кандидатами.
                let my_record = network::dht::DhtRecordBuilder::build(
                    &me.user_id,
                    me.verifying_key.as_bytes().to_vec(),
                    vec![],
                    |bytes| me.sign(bytes).to_bytes().to_vec(),
                );
                if let Err(e) = node.publish_my_record(&my_record) {
                    tracing::error!("Не удалось опубликовать DHT-запись: {e:?}");
                }

                let my_prekey_bundle = network::dht::PreKeyBundleRecordBuilder::build(
                    &me.user_id,
                    &x3dh_identity_public,
                    &signed_prekey_public,
                    &one_time_prekey_publics,
                    |bytes| me.sign(bytes).to_bytes().to_vec(),
                );
                if let Err(e) = node.publish_my_prekey_bundle(&my_prekey_bundle) {
                    tracing::error!("Не удалось опубликовать PreKeyBundle: {e:?}");
                }

                messenger_backend::services::sync::sync_on_startup(
                    &node_cmd_tx_tasks,
                    &registry_for_tasks,
                );

                messenger_backend::services::background::run_background_tasks(
                    node_cmd_tx_tasks,
                    &cfg,
                    registry_for_tasks,
                );

                let incoming_app_handle = app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    while let Some(msg) = incoming_rx.recv().await {
                        let text = String::from_utf8_lossy(&msg.plaintext).into_owned();
                        {
                            let db = db_for_incoming.lock().await;
                            if let Err(e) = db.save_message(&msg.from, "received", &text) {
                                tracing::warn!("Не удалось сохранить входящее сообщение от {}: {e}", msg.from);
                                continue;
                            }
                        }
                        let _ = incoming_app_handle.emit(
                            "message-received",
                            IncomingMessageEvent {
                                from_user_id: msg.from,
                                text,
                            },
                        );
                    }
                });

                node.run_with_commands(node_cmd_rx).await;
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_me,
            get_my_card,
            list_contacts,
            add_contact,
            get_history,
            send_message,
            lookup_user,
            update_relays,
            set_bootstrap_url,
            get_bootstrap_url,
            clear_bootstrap_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
