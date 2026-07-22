use std::sync::Arc;

use messenger_backend::config::Config;
use messenger_backend::identity::Identity;
use messenger_backend::network::{self, NodeHandle};
use messenger_backend::network::relay::RelayRegistry;
use messenger_backend::session::manager::PeerIdentitySource;
use messenger_backend::storage::Database;
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cfg = Config::from_env();
    tracing::info!(
        "Запуск нода, is_relay={}, bootstrap_nodes={}",
        cfg.is_relay,
        cfg.bootstrap_nodes.len()
    );

    let db = Database::open(&cfg.db_path)?;
    tracing::info!("База данных открыта: {}", cfg.db_path);

    // Загружаем существующую identity, либо создаём новую и сохраняем —
    // без этого UserID менялся бы при каждом перезапуске приложения.
    let me = match db.load_identity()? {
        Some((secret_bytes, saved_user_id)) => {
            let secret_bytes: [u8; 32] = secret_bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!(
                    "secret_key в БД повреждён: ожидалось 32 байта, найдено {}",
                    v.len()
                )
            })?;
            let identity = Identity::from_secret_bytes(secret_bytes);
            debug_assert_eq!(identity.user_id, saved_user_id, "UserID не совпал с сохранённым — повреждение данных?");
            tracing::info!("Загружена существующая identity: {}", identity.user_id);
            identity
        }
        None => {
            let identity = Identity::generate();
            db.save_identity(&identity.export_secret_bytes(), &identity.user_id)?;
            tracing::info!("Создана новая identity: {}", identity.user_id);
            identity
        }
    };
    let me = Arc::new(me);

    let identity_db = Database::open(&cfg.db_path)?;
    let identity_source: Arc<dyn PeerIdentitySource> =
        Arc::new(messenger_backend::storage::db::DbPeerIdentitySource::new(identity_db));

    let (x3dh_identity, signed_prekey) = match db.load_x3dh_keys()? {
        Some((identity_bytes, prekey_bytes)) => {
            tracing::info!("Загружены существующие X3DH-ключи");
            (StaticSecret::from(identity_bytes), StaticSecret::from(prekey_bytes))
        }
        None => {
            let identity_secret = network::dht::generate_signed_prekey();
            let prekey_secret = network::dht::generate_signed_prekey();
            db.save_x3dh_keys(&identity_secret.to_bytes(), &prekey_secret.to_bytes())?;
            tracing::info!("Созданы новые X3DH-ключи");
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

    let onion_secret = match db.load_onion_key()? {
        Some(bytes) => {
            tracing::info!("Загружен существующий onion-ключ");
            StaticSecret::from(bytes)
        }
        None => {
            let secret = network::dht::generate_signed_prekey();
            db.save_onion_key(&secret.to_bytes())?;
            tracing::info!("Создан новый onion-ключ");
            secret
        }
    };
    let onion_public = PublicKey::from(&onion_secret);
    tracing::info!(
        "Onion public key (если узел работает как relay): {}",
        hex::encode(onion_public.as_bytes())
    );

    // Создаём пустой реестр relay — заполнится позже от bootstrap
    // через NodeCommand::UpdateRelays. Один экземпляр разделяется
    // между NodeHandle, фоновыми задачами и sync задачей.
    let relay_registry = RelayRegistry::new();

    let (mut node, mut incoming_rx) = NodeHandle::start(
        &cfg,
        me.clone(),
        identity_source,
        x3dh_identity,
        signed_prekey,
        one_time_prekeys,
        onion_secret,
        relay_registry.clone(),
    )
    .await?;
    tracing::info!("libp2p нод поднят: {}", node.local_peer_id);

    // Публикуем DhtRecord с пустым mailbox_candidates — bootstrap ещё
    // не вернул список relay, так что пока публикуем без кандидатов.
    // После получения relay от bootstrap нужно переопубликовать запись
    // с заполненными mailbox_candidates (TODO: NodeCommand::UpdateRelays
    // триггерит RepublishDht автоматически — добавить в следующей итерации
    // при разработке bootstrap-сервера).
    let my_record = network::dht::DhtRecordBuilder::build(
        &me.user_id,
        me.verifying_key.as_bytes().to_vec(),
        vec![], // заполнится после получения relay от bootstrap
        |bytes| me.sign(bytes).to_bytes().to_vec(),
    );
    node.publish_my_record(&my_record)?;

    let my_prekey_bundle = network::dht::PreKeyBundleRecordBuilder::build(
        &me.user_id,
        &x3dh_identity_public,
        &signed_prekey_public,
        &one_time_prekey_publics,
        |bytes| me.sign(bytes).to_bytes().to_vec(),
    );
    node.publish_my_prekey_bundle(&my_prekey_bundle)?;

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<messenger_backend::network::NodeCommand>();

    // Реальный фикс бага "сообщения отправляются, но никуда не доходят":
    // раньше NodeCommand::UpdateRelays никто и никогда не отправлял, так
    // что relay_registry оставался пустым навсегда и dispatcher::send_message
    // валился на select_hops() ещё до выхода пакета в сеть. Смотри
    // services/bootstrap.rs — там подробный разбор.
    if let Some(bootstrap_url) = cfg.bootstrap_url.clone() {
        messenger_backend::services::bootstrap::spawn_bootstrap_fetch(bootstrap_url, cmd_tx.clone());
    } else {
        tracing::warn!(
            "BOOTSTRAP_URL не задан — relay_registry останется пустым, \
             отправка сообщений будет падать с OnionChainTooShort. \
             Задай env BOOTSTRAP_URL=http://<ip_друга>:<port> (без /relays на конце)."
        );
    }

    // Немедленная синхронизация при старте: mailbox fetch у всех relay
    // (если реестр ещё пуст — пропустится без ошибки) + DHT republish.
    messenger_backend::services::sync::sync_on_startup(&cmd_tx, &relay_registry);

    // Background tasks — читают relay из RelayRegistry динамически
    // при каждой итерации, автоматически подхватят новые relay от bootstrap.
    messenger_backend::services::background::run_background_tasks(
        cmd_tx.clone(),
        &cfg,
        relay_registry.clone(),
    );

    // Debug CLI (Termux/без Tauri): help / myid / addcontact / contacts /
    // send / history / relays / exit. Не дублирует логику отправки — всё
    // идёт через тот же cmd_tx и NodeCommand::SendText, которым пользуется
    // Tauri. См. src/cli.rs.
    messenger_backend::cli::spawn_debug_cli(
        cmd_tx.clone(),
        me.clone(),
        cfg.db_path.clone(),
        relay_registry,
    );

    let history_db_path = cfg.db_path.clone();
    tokio::spawn(async move {
        let history_db = match Database::open(&history_db_path) {
            Ok(db) => db,
            Err(e) => {
                tracing::error!("Не удалось открыть БД для сохранения входящих сообщений: {e}");
                return;
            }
        };
        while let Some(msg) = incoming_rx.recv().await {
            let text = String::from_utf8_lossy(&msg.plaintext).into_owned();
            if let Err(e) = history_db.save_message(&msg.from, "received", &text) {
                tracing::warn!("Не удалось сохранить входящее сообщение от {}: {e}", msg.from);
            } else {
                tracing::info!("Сохранено входящее сообщение от {}", msg.from);
            }
            // Явный вывод в stdout для debug CLI — чтобы во второй вкладке
            // Termux было сразу видно "пришло", не копаясь в tracing-логах.
            println!("\n📩 [{}]: {}\n> ", msg.from, text);
        }
    });

    tracing::info!("Node fully initialized. Ожидаем relay от bootstrap (NodeCommand::UpdateRelays).");

    tokio::select! {
        _ = node.run_with_commands(cmd_rx) => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Получен Ctrl+C, завершение работы.");
        }
    }

    Ok(())
}
