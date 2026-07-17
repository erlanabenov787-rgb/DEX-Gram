//! Сгенерированный prost-код из message.proto подключается сюда.
//! build.rs кладёт messenger.rs в OUT_DIR при компиляции.

include!(concat!(env!("OUT_DIR"), "/messenger.rs"));

pub const CURRENT_PROTOCOL_VERSION: u32 = 1;
/// Минимальная версия, с которой мы ещё совместимы "назад".
pub const MIN_SUPPORTED_VERSION: u32 = 1;

pub fn is_compatible(peer_version: u32) -> bool {
    peer_version >= MIN_SUPPORTED_VERSION && peer_version <= CURRENT_PROTOCOL_VERSION
}

/// Фиксированный размер пакета после паддинга — все пакеты одного
/// размера, чтобы наблюдатель не мог различать сообщения по длине.
pub const FIXED_PACKET_SIZE: usize = 4096;

pub fn pad_to_fixed_size(mut data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    if data.len() > FIXED_PACKET_SIZE - 4 {
        anyhow::bail!(
            "payload too large: {} bytes, max {}",
            data.len(),
            FIXED_PACKET_SIZE - 4
        );
    }
    let original_len = data.len() as u32;
    let padding_needed = FIXED_PACKET_SIZE - 4 - data.len();
    data.extend(std::iter::repeat(0u8).take(padding_needed));
    let mut result = original_len.to_le_bytes().to_vec();
    result.extend(data);
    Ok(result)
}

pub fn unpad_from_fixed_size(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() < 4 {
        anyhow::bail!("packet too small to contain length prefix");
    }
    let original_len = u32::from_le_bytes(data[0..4].try_into()?) as usize;
    Ok(data[4..4 + original_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_roundtrip() {
        let original = b"ok".to_vec();
        let padded = pad_to_fixed_size(original.clone()).unwrap();
        assert_eq!(padded.len(), FIXED_PACKET_SIZE);
        let unpadded = unpad_from_fixed_size(&padded).unwrap();
        assert_eq!(unpadded, original);
    }
}
