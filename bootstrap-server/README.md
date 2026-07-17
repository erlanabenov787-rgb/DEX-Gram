# DEX-Gram Bootstrap Server

Лёгкий HTTP-сервис на Rust/axum. Хранит список relay-узлов сети и отдаёт его
клиентам по `GET /relays`. Запускается рядом с relay-нодом на «сервере друга».

## Быстрый старт

```sh
# 1. Запусти relay-нод (messenger-backend с IS_RELAY=true) и запомни его
#    onion_public_key из лога:
#    "Onion public key (если узел работает как relay): aabbccdd..."

IS_RELAY=true \
DB_PATH=/data/relay.db \
LISTEN_PORT=9001 \
./messenger-backend

# 2. Запусти bootstrap-сервер, передав данные этого relay:
RELAY_LIST='[{
  "peer_id":         "12D3KooW...",
  "multiaddr":       "/ip4/<PUBLIC_IP>/tcp/9001",
  "onion_public_key":"aabbccddeeff..."
}]' \
BOOTSTRAP_PORT=8080 \
./bootstrap-server

# 3. В мессенджере (Settings) введи адрес bootstrap-сервера:
#    http://<PUBLIC_IP>:8080
```

## Эндпоинты

| Метод | Путь      | Ответ                                   |
|-------|-----------|-----------------------------------------|
| GET   | `/relays` | `{"relays":[{peer_id,multiaddr,...}]}`  |
| GET   | `/health` | `ok`                                    |

## Переменные окружения

| Переменная        | По умолч. | Описание                                |
|-------------------|-----------|-----------------------------------------|
| `BOOTSTRAP_PORT`  | `8080`    | Порт для прослушивания                  |
| `RELAY_LIST`      | `[]`      | JSON-массив RelayInfo (см. пример выше) |
| `RELAY_LIST_FILE` | —         | Путь к файлу с тем же JSON-массивом     |
| `RUST_LOG`        | `info`    | Уровень логирования                     |

## Сборка

```sh
cargo build --release -p bootstrap-server
# или из корня workspace:
cargo build --release --bin bootstrap-server
```

## systemd unit (пример)

```ini
[Unit]
Description=DEX-Gram Bootstrap Server
After=network.target

[Service]
ExecStart=/usr/local/bin/bootstrap-server
EnvironmentFile=/etc/dexgram/bootstrap.env
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/dexgram/bootstrap.env`:
```env
BOOTSTRAP_PORT=8080
RELAY_LIST=[{"peer_id":"12D3...","multiaddr":"/ip4/1.2.3.4/tcp/9001","onion_public_key":"aabb..."}]
```
