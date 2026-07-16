pub mod lookup;
pub mod publish;
pub mod record;

// Ре-экспорты, чтобы код, который раньше писал `dht::record_key_for_user`
// или `dht::publish_record` (плоский модуль), продолжал компилироваться
// без правок call-сайтов после разбивки на подпапки.
pub use lookup::{
    lookup_prekey_bundle, lookup_relay_descriptor, lookup_user, parse_and_verify_record,
    parse_prekey_bundle_record, DhtLookupSource, LookupRequest,
};
pub use publish::{
    needs_republish, publish_prekey_bundle, publish_record, publish_relay_descriptor,
    republish_if_needed,
};
pub use record::{
    generate_one_time_prekeys, generate_signed_prekey, prekey_bundle_key_for_user,
    record_key_for_user, relay_descriptor_key_for_relay, DhtRecordBuilder,
    PreKeyBundleRecordBuilder, RelayDescriptorRecordBuilder,
};
