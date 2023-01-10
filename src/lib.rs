// Copyright (C) 2022 Wire Swiss GmbH <support@wire.com>
// Based on libsignal-protocol-java by Open Whisper Systems
// https://github.com/WhisperSystems/libsignal-protocol-java.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

pub mod error;
pub mod internal;
pub mod keys;
pub mod message;
pub mod session;

#[cfg(feature = "cryptobox-identity")]
pub mod identity;

/// It's here for compatibility purposes, since it's not needed at all anymore
#[must_use]
pub fn init() -> bool {
    true
}

pub use crate::internal::types::{DecodeError, EncodeError};
