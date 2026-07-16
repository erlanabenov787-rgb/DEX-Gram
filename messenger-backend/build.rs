fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ВАЖНО: network/p2p.rs (MessengerCodec) и network/dispatcher.rs уже
    // делают bincode::serialize(&packet) на сгенерированных prost-типах
    // (Packet и т.д.) — без этих serde-атрибутов сгенерированный код их
    // не реализует, и bincode::serialize там просто не скомпилируется.
    prost_build::Config::new()
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&["src/protocol/message.proto"], &["src/protocol/"])?;
    Ok(())
}
