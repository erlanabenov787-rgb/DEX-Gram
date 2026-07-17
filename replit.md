# Messenger Backend

Приватный мессенджер с onion routing (libp2p) и end-to-end шифрованием (Double Ratchet + X3DH). Rust backend + Tauri desktop/mobile.

## Run & Operate

- `cd messenger-backend && cargo run` — запустить CLI-ноду
- `cd src-tauri && cargo tauri dev` — запустить Tauri-приложение
- Обязательные переменные: `BOOTSTRAP_NODES` — multiaddr через запятую

## Stack

- Rust + libp2p (Kademlia DHT, Noise, QUIC, TCP)
- Onion routing (X25519), Double Ratchet, X3DH
- SQLite (rusqlite), Tauri v2

## Where things live

- `messenger-backend/src/config/settings.rs` — `Config`: единственная точка конфигурации
- `messenger-backend/src/network/relay/registry.rs` — `RelayRegistry`: динамический реестр relay
- `messenger-backend/src/network/p2p.rs` — `NodeHandle` + `NodeCommand` (включая `UpdateRelays`)
- `messenger-backend/src/services/background.rs` — фоновые задачи (dummy traffic, mailbox fetch, DHT republish)
- `src-tauri/src/lib.rs` — Tauri commands: `update_relays` для получения relay от bootstrap

## Architecture decisions

- **Relay получаются от bootstrap, не из конфига.** Пользователь вводит только bootstrap. Список relay приходит через `NodeCommand::UpdateRelays` → `RelayRegistry`. Фронтенд вызывает Tauri command `update_relays` после подключения к bootstrap.
- **RelayRegistry — единственный источник истины о relay.** Заменяет старый `static_relays` в конфиге. `Arc<RelayRegistry>` шарится между `NodeHandle`, background задачами и sync. Обновление атомарное через `RwLock`.
- **Background задачи читают relay динамически.** Каждую итерацию читают `registry.relay_ids()` — автоматически подхватывают новые relay после ответа bootstrap, без перезапуска.
- **`StaticRelay` — type alias для `RelayInfo`** ради обратной совместимости. `static_source.rs` сохранён для совместимости, но больше не используется в production пути.
- **Bootstrap сервер пока не реализован.** Клиент готов принять список relay через `NodeCommand::UpdateRelays` / Tauri `update_relays`.

## Product

- Приватный мессенджер с onion routing (3-5 хопов): никто, включая relay-узлы, не знает одновременно кто и кому пишет
- End-to-end шифрование: relay видят только зашифрованные слои, не содержимое
- Mailbox: сообщения накапливаются на relay пока получатель оффлайн
- DHT (Kademlia): поиск пользователей по UserID без централизованного сервера

## User preferences

_Populate as you build._

## Gotchas

- Bootstrap nodes → relay → onion chain → mailbox. Без relay цепочка не строится.
- `BOOTSTRAP_NODES` env var — единственная обязательная сетевая настройка для пользователя.
- `RelayRegistry` пуст при старте: background задачи корректно это обрабатывают (пропускают итерацию).
- `static_source.rs` и `StaticOnionKeySource` оставлены — они больше не используются в продакшн пути, но нужны для обратной совместимости.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
