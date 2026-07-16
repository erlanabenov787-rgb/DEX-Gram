use std::sync::Arc;

use messenger_backend::config::Config;
use messenger_backend::identity::Identity;
use messenger_backend::network::{self, NodeCommand, NodeHandle};
use messenger_backend::session::manager::PeerIdentitySource;
use messenger_backend::storage::db::DbPeerIdentitySource;
use messenger_backend::storage::Database;
use serde::Serialize;
use tauri::{Emitter, State};
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

fn db_path() -> String {
    // На Android tauri подставит app data dir через app.path() в реальной
    // прод-версии; для MVP держим относительный путь как в исходном main.rs.
    "./messenger.db".to_string()
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

/// Раньше эта команда только писала в локальную БД и ничего никуда не
/// отправляла ("TODO: добавить NodeHandle в AppState"). Теперь она
/// реально просит node loop зашифровать+заонионить+отправить сообщение,
/// и только при успехе сохраняет его в историю как "sent". Если
/// отправка не удалась (например: нет сессии с этим контактом ещё, или
/// не настроено достаточно static_relays — см. config::StaticRelay),
/// команда вернёт ошибку, а не тихо соврёт что сообщение ушло.
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db = Database::open(&db_path()).expect("failed to open local db");

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
    // X3DH-ключи (identity + signed prekey) — тот же load-or-generate
    // паттерн, что и у `me` выше, тем же самым `db` соединением (это ещё
    // синхронный участок, до spawn, так что std::sync::Mutex вокруг
    // Database изнутри storage/db.rs тут ничему не мешает). Персистентность
    // нужна по той же причине, что у ed25519 identity: без неё
    // опубликованный PreKeyBundle ссылался бы на мёртвый ключ после
    // каждого перезапуска приложения.
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

    // Onion-секрет — тот же load-or-generate паттерн, что и в CLI
    // main.rs (см. комментарий там и у storage/db.rs::save_onion_key).
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

    // Database теперь Send+Sync сама по себе (Connection у неё за
    // std::sync::Mutex — см. storage/db.rs), так что Arc<Mutex<Database>>
    // формально можно было бы переиспользовать и здесь. Но берём отдельное
    // соединение с той же базой: identity_source дёргается из session
    // manager на каждое входящее сообщение, и не хочется, чтобы это
    // блокировалось UI-командами, держащими db.lock() (или наоборот).
    let identity_db = Database::open(&db_path()).expect("failed to open identity-lookup db");
    let identity_source: Arc<dyn PeerIdentitySource> = Arc::new(DbPeerIdentitySource::new(identity_db));

    let (node_cmd_tx, node_cmd_rx) = mpsc::unbounded_channel::<NodeCommand>();
    // Клон для фоновых задач (background + sync) — оригинал уходёт в
    // AppState для обработки UI-команд (send_message и т.д.).
    let node_cmd_tx_tasks = node_cmd_tx.clone();

    tauri::Builder::default()
        .manage(AppState {
            db: db.clone(),
            me: me.clone(),
            node_commands: node_cmd_tx,
        })
        .setup(move |app| {
            let app_handle = app.handle().clone();
            let me = me.clone();
            let db_for_incoming = db.clone();

            // Node запускаем в фоне: поднимает libp2p swarm и держит
            // NodeHandle внутри run_with_commands, обслуживая как входящий
            // трафик, так и команды из Tauri commands (см. send_message).
            //
            // ЧЕСТНО: cfg.static_relays по умолчанию пустой (см.
            // config::settings::Config::default) — без минимум 3
            // сконфигурированных relay онион-цепочка не построится и
            // send_message будет падать с "недостаточно known relays".
            // Это тот же самый пробел, что и раньше в CLI-бинарнике
            // (main.rs), не что-то новое, что вносит это изменение.
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

                // ОБНОВЛЕНИЕ: раньше этот блок вообще отсутствовал — Tauri-
                // приложение поднимало нод, но никогда не публиковало
                // DhtRecord, так что никто не мог найти этого пользователя
                // по UserID вообще (отдельный, более базовый пробел, чем
                // отсутствие PreKeyBundle). Теперь публикуем оба, тем же
                // паттерном что и CLI main.rs.
                // mailbox_candidates = relay_id-шники из cfg.static_relays — тот
                // же временный воркэраунд, что и в CLI main.rs (см. комментарий там).
                let mailbox_candidates: Vec<String> =
                    cfg.static_relays.iter().map(|r| r.relay_id.clone()).collect();
                let my_record = network::dht::DhtRecordBuilder::build(
                    &me.user_id,
                    me.verifying_key.as_bytes().to_vec(),
                    mailbox_candidates,
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

                // Немедленная синхронизация при старте: mailbox fetch у всех
                // known relay + DHT republish (не ждя первого срабатывания
                // background-задач). Тот же паттерн что и в CLI main.rs.
                messenger_backend::services::sync::sync_on_startup(
                    &node_cmd_tx_tasks,
                    &cfg.static_relays,
                );

                // Фоновые задачи: dummy traffic, периодический mailbox fetch,
                // DHT republish каждые DHT_REPUBLISH_INTERVAL_SECS.
                messenger_backend::services::background::run_background_tasks(
                    node_cmd_tx_tasks,
                    &cfg,
                );

                // Входящие расшифрованные сообщения: сохраняем в историю
                // и уведомляем UI событием, вместо того чтобы фронтенд
                // должен был сам их как-то опрашивать.
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
            list_contacts,
            add_contact,
            get_history,
            send_message
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
