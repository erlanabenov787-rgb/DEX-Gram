# messenger — backend + Tauri frontend

## Структура

```
messenger-backend/   # твой оригинальный Rust P2P-нод (libp2p, DHT, onion, crypto) — не тронут
src-tauri/            # Tauri-обёртка: Rust-команды (invoke) + сборка под Android/desktop
frontend/              # UI (чистый HTML/CSS/JS), рендерится внутри Tauri webview
.github/workflows/     # CI-сборка APK на GitHub Actions (не на телефоне)
```

## Как гонять

1. Пуш в `main` на GitHub → workflow `Build Android APK` соберёт APK
   и положит его в Actions → Artifacts (`messenger-apk`).
2. Для десктоп-теста локально (если будет доступ к машине с Rust):
   `cd src-tauri && cargo tauri dev`.

## Что реально работает сейчас

- Identity (генерация/восстановление ключа, UserID) — из твоего `identity.rs`, без изменений.
- Контакты и история сообщений — читаются/пишутся через `storage::Database` (SQLite), тоже без изменений в логике.
- UI: список контактов → тред → отправка сообщения, всё на локальной SQLite.

## Что ещё НЕ подключено (важно)

В твоём `main.rs` уже было отмечено: `SessionManager`, `dispatcher` и реальная
отправка через P2P/onion-сеть — MVP-заглушка. Команда `send_message` в
`src-tauri/src/lib.rs` сейчас **только сохраняет исходящее сообщение локально**,
без реальной шифрованной отправки через сеть. Как только заведёшь
`NodeHandle` + `SessionManager` внутри `AppState` (они у тебя уже написаны
в `network::p2p` и `session::manager`), в `send_message` добавляется вызов
шифрования через `SessionManager::encrypt_for` и отправка через
`dispatcher` — тред UI трогать не придётся, он просто читает БД.

## Иконки

`src-tauri/icons/*` — временные заглушки (сплошной цвет), чтобы бандл собирался.
Замени на нормальные, когда будет арт.
