//! Relay service — пересылка пакетов между relay-узлами и обработка
//! входящих onion-пакетов на этом узле.

use crate::network::onion::OnionPacket;
use crate::network::{OutboundPacket, OutboundSender, RelayId};
use anyhow::Result;
use tracing::info;

/// Реально ставит пакет в очередь на отправку следующему хопу.
/// Само физическое отправление делает `p2p::NodeHandle`, вычитывая
/// `outbound` канал в event loop — см. комментарий в network/mod.rs.
pub async fn forward_to_next_hop(
    next_hop: RelayId,
    packet: OnionPacket,
    outbound: &OutboundSender,
) -> Result<()> {
    info!("Forwarding onion packet to next hop: {}", next_hop);

    let wrapped = crate::protocol::Packet {
        protocol_version: crate::protocol::CURRENT_PROTOCOL_VERSION,
        r#type: crate::protocol::PacketType::RelayForward.into(),
        encrypted_payload: packet.layers,
        sender_signature: Vec::new(),
        padding_len: 0,
        recipient_user_id: String::new(),
    };

    outbound
        .send(OutboundPacket {
            target_peer_id: next_hop,
            packet: wrapped,
        })
        .map_err(|_| anyhow::anyhow!("outbound channel closed — node event loop stopped?"))?;

    Ok(())
}

pub async fn forward_packet(_packet: crate::protocol::Packet) -> Result<()> {
    // Legacy / placeholder
    info!("Relay forward requested");
    Ok(())
}