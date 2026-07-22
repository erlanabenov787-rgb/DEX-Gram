//! Debug CLI поверх уже существующего backend-а.
//!
//! Цель: дать возможность гонять весь мессенджер из Termux (два таба —
//! два процесса с разными db_path/портом) без сборки Android APK и без
//! Tauri UI. Никакой новой логики отправки/приёма здесь нет — CLI только
//! читает stdin и дёргает то, что уже есть:
//!   - отправка сообщения -> NodeCommand::SendText (тот же путь, что и Tauri)
//!   - контакты/история -> Database (storage/db.rs), как и раньше
//!   - список relay -> RelayRegistry::all_entries() (то же, что видит
//!     dispatcher::send_message при выборе onion-хопов)
//!
//! Работает как отдельная tokio-задача параллельно с
//! `node.run_with_commands(cmd_rx)` — общаются только через cmd_tx
//! (тот же канал, которым пользуется Tauri command handler), поэтому
//! существующий `tokio::select!` в p2p.rs не тронут.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;

use crate::identity::Identity;
use crate::network::relay::RelayRegistry;
use crate::network::NodeCommand;
use crate::storage::Database;

const HELP_TEXT: &str = r#"Commands:
  help                          - показать эту справку
  myid                          - показать свой UserID и публичный ключ (hex)
  addcontact <userId> <pubkeyHex> [name]
                                 - добавить контакт (нужно ПЕРЕД send,
                                   иначе шифрование упадёт с IdentityKeyNotFound)
  contacts                      - список сохранённых контактов
  send <userId> <текст...>      - отправить сообщение (NodeCommand::SendText)
  history <userId> [limit]      - история сообщений с контактом
  relays                        - relay, известные локально (из bootstrap)
  exit                          - завершить процесс
"#;

/// Запускает debug CLI как отдельную tokio-задачу.
///
/// `db_path` — тот же путь, что и у основной БД (main.rs); CLI открывает
/// собственное sqlite-соединение (так же, как это уже делает history-таск
/// в main.rs для входящих сообщений) — отдельные соединения к одному
/// файлу в rusqlite это нормальный и дешёвый паттерн, уже используемый
/// в проекте (см. комментарий у DbPeerIdentitySource в storage/db.rs).
pub fn spawn_debug_cli(
    cmd_tx: UnboundedSender<NodeCommand>,
    me: Arc<Identity>,
    db_path: String,
    relay_registry: Arc<RelayRegistry>,
) {
    tokio::spawn(async move {
        let db = match Database::open(&db_path) {
            Ok(db) => db,
            Err(e) => {
                tracing::error!("Debug CLI: не удалось открыть БД ({db_path}): {e}");
                return;
            }
        };

        let mut stdout = tokio::io::stdout();
        let mut lines = BufReader::new(tokio::io::stdin()).lines();

        println!("\nDebug CLI готов. Наберите 'help' для списка команд.");

        loop {
            let _ = stdout.write_all(b"> ").await;
            let _ = stdout.flush().await;

            let line = match lines.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => {
                    tracing::info!("Debug CLI: stdin закрыт (EOF), CLI-задача завершена");
                    return;
                }
                Err(e) => {
                    tracing::warn!("Debug CLI: ошибка чтения stdin: {e}");
                    return;
                }
            };

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let mut parts = line.splitn(2, char::is_whitespace);
            let cmd = parts.next().unwrap_or("").to_lowercase();
            let rest = parts.next().unwrap_or("").trim();

            match cmd.as_str() {
                "help" => {
                    print!("{HELP_TEXT}");
                }
                "myid" => {
                    println!("UserID:     {}", me.user_id);
                    println!(
                        "PublicKey:  {}",
                        hex::encode(me.verifying_key.as_bytes())
                    );
                    println!(
                        "(отправь эти две строки собеседнику — он должен ввести их через 'addcontact', и наоборот)"
                    );
                }
                "addcontact" => {
                    let mut args = rest.splitn(3, char::is_whitespace);
                    let user_id = args.next().unwrap_or("");
                    let pubkey_hex = args.next().unwrap_or("");
                    let name = args.next().unwrap_or(user_id).trim();

                    if user_id.is_empty() || pubkey_hex.is_empty() {
                        println!("Использование: addcontact <userId> <pubkeyHex> [name]");
                        continue;
                    }
                    match hex::decode(pubkey_hex) {
                        Ok(bytes) if bytes.len() == 32 => {
                            match db.add_contact(user_id, name, &bytes) {
                                Ok(()) => println!("✓ contact added: {user_id} ({name})"),
                                Err(e) => println!("✗ ошибка БД: {e}"),
                            }
                        }
                        Ok(bytes) => {
                            println!(
                                "✗ pubkeyHex должен раскодироваться в 32 байта (ed25519), получено {}",
                                bytes.len()
                            );
                        }
                        Err(e) => println!("✗ невалидный hex: {e}"),
                    }
                }
                "contacts" => match db.list_contacts() {
                    Ok(list) if list.is_empty() => println!("(контактов пока нет)"),
                    Ok(list) => {
                        for (user_id, name) in list {
                            println!("  {user_id}  {name}");
                        }
                    }
                    Err(e) => println!("✗ ошибка БД: {e}"),
                },
                "send" => {
                    let mut args = rest.splitn(2, char::is_whitespace);
                    let to = args.next().unwrap_or("").to_string();
                    let text = args.next().unwrap_or("").to_string();

                    if to.is_empty() || text.is_empty() {
                        println!("Использование: send <userId> <текст>");
                        continue;
                    }

                    let (respond_to, resp_rx) = tokio::sync::oneshot::channel();
                    if cmd_tx
                        .send(NodeCommand::SendText {
                            to: to.clone(),
                            text: text.clone().into_bytes(),
                            respond_to,
                        })
                        .is_err()
                    {
                        println!("✗ канал команд закрыт, node уже остановлен");
                        continue;
                    }

                    match resp_rx.await {
                        Ok(Ok(())) => {
                            println!("✓ sent");
                            // Сохраняем в локальную историю тем же способом, каким
                            // main.rs уже сохраняет входящие (save_message) — чтобы
                            // 'history' показывала обе стороны переписки.
                            if let Err(e) = db.save_message(&to, "sent", &text) {
                                tracing::warn!("Не удалось сохранить отправленное сообщение в историю: {e}");
                            }
                        }
                        Ok(Err(e)) => {
                            println!("✗ ошибка отправки: {e:?}");
                            println!(
                                "  (частые причины: контакт не добавлен через addcontact -> IdentityKeyNotFound; \
                                 relay ещё не получены от bootstrap -> OnionChainTooShort — проверь 'relays')"
                            );
                        }
                        Err(_) => println!("✗ node не ответил (respond_to канал закрылся)"),
                    }
                }
                "history" => {
                    let mut args = rest.splitn(2, char::is_whitespace);
                    let user_id = args.next().unwrap_or("");
                    let limit: u32 = args
                        .next()
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(50);

                    if user_id.is_empty() {
                        println!("Использование: history <userId> [limit]");
                        continue;
                    }

                    match db.get_history(user_id, limit) {
                        Ok(rows) if rows.is_empty() => println!("(истории с {user_id} пока нет)"),
                        Ok(rows) => {
                            for (direction, text, sent_at) in rows {
                                let arrow = if direction == "sent" { "->" } else { "<-" };
                                println!("[{sent_at}] {arrow} {text}");
                            }
                        }
                        Err(e) => println!("✗ ошибка БД: {e}"),
                    }
                }
                "relays" => {
                    let entries = relay_registry.all_entries();
                    if entries.is_empty() {
                        println!(
                            "(relay пока нет — bootstrap ещё не ответил или BOOTSTRAP_URL не задан. \
                             Без этого send всегда будет падать с OnionChainTooShort.)"
                        );
                    } else {
                        for entry in entries {
                            println!("  {}  {}", entry.relay_id, entry.address);
                        }
                    }
                }
                "exit" | "quit" => {
                    println!("Bye.");
                    std::process::exit(0);
                }
                other => {
                    println!("Неизвестная команда: '{other}'. Наберите 'help'.");
                }
            }
        }
    });
}
