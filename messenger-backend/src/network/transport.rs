//! Транспортный уровень. Здесь можно добавить дополнительные обёртки над libp2p если нужно.

use libp2p::Multiaddr;

pub fn parse_multiaddr(addr: &str) -> anyhow::Result<Multiaddr> {
    addr.parse().map_err(|e| anyhow::anyhow!("Bad multiaddr: {}", e))
}