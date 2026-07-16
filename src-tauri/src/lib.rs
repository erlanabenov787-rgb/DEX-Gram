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
            msgs.reverse(); // из БД идёт DESC, в UI нужен хронологический порядок
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
    let (respond_to, response) = oneshot::channel();
    state
        .node_commands
        .send(NodeCommand::SendText {
            to: contact_user_id.clone(),
            text: text.clone().into_bytes(),
            respond_to,
        })
        .map_err(|_| "network node не запущен (task завершился?)".to_string())?;

    response
        .await
        .map_err(|_| "network node не ответил на запрос отправки".to_string())?
        .map_err(|e| e.to_string())?;

    let db = state.db.lock().await;
    db.save_message(&contact_user_id, "sent", &text)
        .map_err(|e| e.to_string())
}

/// Возвращает собственную карточку для показа QR-кода.
///
/// Фронтенд кодирует строку `user_id:public_key_hex` в QR (например через
/// qrcode.js / qrcodejs). Собеседник сканирует, парсит по ":" и вызывает
/// add_contact.
#[tauri::command]
fn get_my_card(state: State<AppState>) -> String {
    let pubkey_hex = hex::encode(state.me.verifying_key.as_bytes());
    format!("{}:{}", state.me.user_id, pubkey_hex)
}

/// Найти пользователя по UserID через DHT.
///
/// Запускает Kademlia-поиск и ждёт ответа (таймаут 30 сек).
/// Возвращает `{ user_id, public_key_hex }` если нашёл, иначе ошибку.
#[tauri::command]
async fn lookup_user(
    state: State<'_, AppState>,
    user_id: String,
) -> Result<MeInfo, String> {
    let (tx, rx) = oneshot::channel();
    state
        .node_commands
        .send(NodeCommand::LookupUser {
            user_id: user_id.clone(),
            respond_to: tx,
        })
        .map_err(|_| "network node не запущен".to_string())?;

    let record = tokio::time::timeout(std::time::Duration::from_secs(30), rx)
        .await
        .map_err(|_| format!("таймаут: пользователь {user_id} не найден в DHT за 30 сек"))?
        .map_err(|_| "node закрыл канал до ответа".to_string())?
        .map_err(|e| e.to_string())?;

    Ok(MeInfo {
        user_id: record.user_id,
        public_key_hex: hex::encode(&record.public_key),
    })
}

/// Передаёт список relay-узлов, полученных от bootstrap, в network node.
///
/// Фронтенд вызывает эту команду после того как получил список relay
/// от bootstrap-сервера. Пользователь relay не видит и не вводит вручную.
///
/// После вызова NodeHandle:
/// - обновляет RelayRegistry (виден всем фоновым задачам сразу)
/// - подключается к новым relay
/// - записывает их репутацию в локальную БД
/// - отправляет начальный mailbox fetch к каждому relay
#[tauri::command]
async fn update_relays(
    state: State<'_, AppState>,
    relays: Vec<RelayInfoDto>,
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

    state
        .node_commands
        .send(NodeCommand::UpdateRelays { relays: entries })
        .map_err(|_| "network node не запущен".to_string())?;

    Ok(())
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
                    let identity = Identity::from_secret_bytes(secret_bytes);
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

            let me = Arc::new(me);
            let db = Arc::new(Mutex::new(db));

            let identity_db = Database::open(&path).expect("failed to open identity-lookup db");
            let identity_source: Arc<dyn PeerIdentitySource> = Arc::new(DbPeerIdentitySource::new(identity_db));

            // Создаём пустой реестр relay — заполнится через update_relays()
            // (Tauri command), который фронтенд вызывает после получения
            // relay-списка от bootstrap.
            let relay_registry = RelayRegistry::new();

            let (node_cmd_tx, node_cmd_rx) = mpsc::unbounded_channel::<NodeCommand>();
            let node_cmd_tx_tasks = node_cmd_tx.clone();

            app.manage(AppState {
                db: db.clone(),
                me: me.clone(),
                node_commands: node_cmd_tx,
            });

            let me = me.clone();
            let db_for_incoming = db.clone();
            let registry_for_tasks = relay_registry.clone();

            tauri::async_runtime::spawn(async move {
                let cfg = Config::from_env();
                let (mut node, mut incoming_rx) = match NodeHandle::start(
                    &cfg,
                    me.clone(),
                    identity_source,
                    x3dh_identity,
                    signed_prekey,
                    one_time_prekeys,
                    onion_secret,
                    relay_registry,
                )
                .await
                {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::error!("Не удалось поднять network node: {e:?}");
                        return;
                    }
                };
                tracing::info!("libp2p нод поднят: {}", node.local_peer_id);

                // Публикуем DhtRecord с пустым mailbox_candidates —
                // заполнится после получения relay от bootstrap через
                // update_relays (Tauri command).
                let my_record = network::dht::DhtRecordBuilder::build(
                    &me.user_id,
                    me.verifying_key.as_bytes().to_vec(),
                    vec![], // заполнится после bootstrap
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

                // Немедленная синхронизация: если реестр пуст (bootstrap ещё
                // не ответил) — sync пропустит mailbox fetch без ошибки.
                messenger_backend::services::sync::sync_on_startup(
                    &node_cmd_tx_tasks,
                    &registry_for_tasks,
                );

                // Фоновые задачи: читают relay из RelayRegistry динамически.
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
