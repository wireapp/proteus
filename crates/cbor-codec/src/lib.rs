// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

//! CBOR (RFC 7049) encoder and decoder implementations.

pub mod decoder;
pub mod encoder;
pub mod skip;
pub mod slice;
pub mod types;
pub mod value;

#[cfg(feature = "random")]
pub mod random;

pub use crate::decoder::{maybe, opt, or_break};
pub use crate::decoder::{Config, DecodeError, DecodeResult, Decoder, GenericDecoder};
pub use crate::encoder::{EncodeError, EncodeResult, Encoder, GenericEncoder};
