// Re-export lzy for convenience
#[cfg(feature = "lzy")]
pub use lzy;

pub mod core {
    pub mod group_keys;
    pub use group_keys::*;
    pub mod keys;
    pub mod known_state;
    pub mod nonce;
    pub mod peer_known_state;
    pub mod priority;
    pub mod session_log;
    pub mod session_map;
    pub mod storage_reconciliation;
    pub use keys::*;
    pub use nonce::*;
    pub use priority::*;
    pub use session_log::*;
    pub use session_map::*;
    pub mod node;
    pub use node::*;
    pub mod cache;
    pub use cache::*;
    pub mod error;
    pub use error::*;
    pub mod config;
    pub use config::*;
    pub mod group_engine;
    pub use group_engine::*;
    pub mod group_key_state;
    pub use group_key_state::*;
    // Test-only: shared serde fixture structs for the group-key golden-replay
    // tests below. No production code path, so gated to `cfg(test)`.
    #[cfg(test)]
    pub(crate) mod group_key_test_support;
    pub mod group_key_rotation;
    pub use group_key_rotation::*;
    pub mod group_key_extend;
    pub use group_key_extend::*;
    pub mod group_key_membership;
    pub use group_key_membership::*;
    // Leaf helpers shared by the materialized content views below. Internal
    // (`pub(crate)`), so no glob re-export.
    pub mod co_content;
    pub mod co_map;
    pub use co_map::*;
    pub mod co_stream;
    pub use co_stream::*;
    pub mod co_list;
    pub use co_list::*;
    // Native, read-only reproduction of LocalNode's pure identity-resolution
    // slice. Test-only oracle: no glob re-export, zero production call sites.
    pub mod identity_resolution;
}

pub mod hash {
    pub mod blake3;
    pub use blake3::*;
}
pub mod crypto {
    pub mod ed25519;
    pub mod encrypt;
    pub mod key_secret;
    pub mod seal;
    pub mod signature;
    pub mod x25519;
    pub mod xsalsa20;

    pub use ed25519::*;
    pub use encrypt::*;
    pub use key_secret::*;
    pub use seal::*;
    pub use signature::*;
    pub use x25519::*;
    pub use xsalsa20::*;
    pub mod error;
    pub use error::*;
}
