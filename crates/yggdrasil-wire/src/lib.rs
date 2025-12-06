//! Wire protocol encoding/decoding for the Yggdrasil network.
//!
//! This crate implements the binary wire protocol used for communication
//! between Yggdrasil nodes. It provides encoding and decoding functions
//! for all protocol message types.

mod encoding;
mod framing;
mod packet;
mod types;

pub use encoding::*;
pub use framing::*;
pub use packet::*;
pub use types::*;

use yggdrasil_types::WireError;

/// Result type for wire protocol operations.
pub type WireResult<T> = Result<T, WireError>;
