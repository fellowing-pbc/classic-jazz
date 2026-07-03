//! Group engine: role model, permission comparators, and CoValue key
//! classifiers ported from `packages/cojson/src/permissions.ts` and
//! `packages/cojson/src/coValues/group.ts`.
//!
//! `engine` (validation/read-side algorithms) is added in a later task; this
//! module currently only exposes the foundation types and key classifiers.

pub mod classify;
pub mod tx_view;
pub mod types;

pub use classify::*;
pub use tx_view::*;
pub use types::*;
