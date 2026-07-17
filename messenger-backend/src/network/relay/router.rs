//! Router — принимает решение, как маршрутизировать входящий onion-пакет.
//! Здесь можно добавить логику: я ли я exit-узел? Есть ли у меня mailbox для этого пользователя?
//! Или просто форвард дальше.

use crate::network::mailbox::MailboxService;
use crate::network::onion::PeelResult;
use crate::network::{OutboundSender, RelayId};
use anyhow::Result;

pub async fn decide_and_route(
    result: PeelResult,
    _our_relay_id: &RelayId,
    mailbox_service: &MailboxService,
    outbound: &OutboundSender,
) -> Result<()> {
    match result {
        PeelResult::Forward { next_hop, remaining } => {
            // Просто переслать следующему
            crate::network::relay::service::forward_to_next_hop(next_hop, remaining, outbound).await?;
        }
        PeelResult::Exit { payload, destination } => {
            // Мы exit-узел — решаем, куда положить payload
            match destination {
                crate::types::DestinationHint::Mailbox(user_id) => {
                    crate::network::mailbox::service::store_for_user(mailbox_service, &user_id, payload).await?;
                }
                crate::types::DestinationHint::DirectPeer(_) => {
                    // Прямая доставка (редко)
                    tracing::info!("Exit: direct delivery requested");
                }
            }
        }
    }
    Ok(())
}