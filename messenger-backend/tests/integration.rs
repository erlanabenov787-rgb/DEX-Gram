//! Интеграционный тест уровня "логика", без реального libp2p-транспорта
//! (тот тест — отдельная история, нужны 2 реальных запущенных процесса).
//! Тут проверяем что весь путь данных end-to-end корректен:
//! Alice шифрует → заворачивает в onion → 3 relay пересылают →
//! mailbox хранит → Bob забирает и расшифровывает.

use messenger_backend::crypto::ratchet::DoubleRatchet;
use messenger_backend::network::mailbox::MailboxStore;
use messenger_backend::network::relay::{ForwardAction, RelayForwarder, RouteBuilder};

#[test]
fn full_message_flow_alice_to_bob() {
    // 1. Alice и Bob согласовали общий секрет (в реальности — через X3DH)
    let shared_secret = [7u8; 32];
    let mut alice_ratchet = DoubleRatchet::new(shared_secret);
    let mut bob_ratchet = DoubleRatchet::new(shared_secret);

    // 2. Alice шифрует сообщение
    let envelope = alice_ratchet.encrypt(b"privet, kak dela?").unwrap();
    let serialized_envelope = bincode::serialize(&envelope).unwrap();

    // 3. Заворачиваем в onion через 3 relay
    let route = vec![
        "relay_alpha".to_string(),
        "relay_beta".to_string(),
        "relay_gamma".to_string(),
    ];
    let wrapped = RouteBuilder::wrap_in_onion(serialized_envelope, &route, |_id, bytes| {
        bytes.to_vec() // в реальности тут транспортное шифрование для каждого relay
    });

    // 4. Каждый relay по очереди снимает свой слой
    let mut current = wrapped;
    for expected_hop in &route[1..] {
        let action = RelayForwarder::process_incoming(&current, |b| Ok(b.to_vec())).unwrap();
        match action {
            ForwardAction::Forward { to, payload } => {
                assert_eq!(&to, expected_hop);
                current = payload;
            }
            ForwardAction::DeliverToMailbox(_) => panic!("слишком рано для доставки"),
        }
    }

    // Последний relay (relay_gamma) доставляет в mailbox
    let action = RelayForwarder::process_incoming(&current, |b| Ok(b.to_vec())).unwrap();
    let final_payload = match action {
        ForwardAction::DeliverToMailbox(payload) => payload,
        _ => panic!("ожидалась доставка в mailbox"),
    };

    // 5. Mailbox хранит, Bob оффлайн
    let mut mailbox = MailboxStore::new();
    let bob_id = "bob_userid".to_string();
    mailbox.store(&bob_id, final_payload).unwrap();

    // 6. Bob приходит онлайн, забирает сообщения
    let fetched = mailbox.fetch_and_clear(&bob_id);
    assert_eq!(fetched.len(), 1);

    // 7. Bob расшифровывает
    let envelope: messenger_backend::crypto::EncryptedEnvelope =
        bincode::deserialize(&fetched[0]).unwrap();
    let plaintext = bob_ratchet.decrypt(&envelope).unwrap();

    assert_eq!(plaintext, b"privet, kak dela?");
}
