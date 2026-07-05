//! Shared serde fixture structs for the group-key golden-replay tests. These
//! deserialize the `data/group_key_*/*.json` fixtures (exported from real TS)
//! that `group_key_membership` / `group_key_rotation` / `group_key_extend`
//! replay against the native write paths. Each struct was previously declared
//! byte-for-byte identically in those modules' `#[cfg(test)] mod fixtures`;
//! consolidated here so there is one definition. Test-only.

use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct KeyPairFx {
    pub(crate) id: String,
    pub(crate) secret: String,
}

#[derive(Deserialize)]
pub(crate) struct MemberFx {
    #[serde(rename = "memberKey")]
    pub(crate) member_key: String,
    #[serde(rename = "agentSealerId")]
    pub(crate) agent_sealer_id: String,
}

#[derive(Deserialize)]
pub(crate) struct ParentFx {
    #[serde(rename = "readKeyId")]
    pub(crate) read_key_id: String,
    #[serde(rename = "readKeySecret")]
    pub(crate) read_key_secret: String,
}

#[derive(Deserialize)]
pub(crate) struct WriteFx {
    pub(crate) field: String,
    pub(crate) value: String,
}
