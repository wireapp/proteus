// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
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

use crate::internal::keys::IdentityKey;

#[derive(Debug, thiserror::Error)]
pub enum InternalError {
    #[error("No session found for session tag.")]
    NoSessionForTag,
    #[error("Length of the KDF is invalid: invalid number of blocks, too large output")]
    InvalidKdfLength,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl PartialEq for InternalError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (InternalError::NoSessionForTag, InternalError::NoSessionForTag) => true,
            (InternalError::InvalidKdfLength, InternalError::InvalidKdfLength) => true,
            (InternalError::IoError(e1), InternalError::IoError(e2)) if e1.kind() == e2.kind() => {
                true
            }
            _ => false,
        }
    }
}

impl From<hkdf::InvalidLength> for InternalError {
    fn from(_: hkdf::InvalidLength) -> Self {
        Self::InvalidKdfLength
    }
}

// EncodeError //////////////////////////////////////////////////////////////

pub type EncodeResult<A> = Result<A, EncodeError>;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("Internal error: {0}")]
    Internal(#[from] InternalError),
    #[error("CBOR encoder error: {0}")]
    Encoder(#[from] minicbor::encode::Error<()>),
}

// DecodeError //////////////////////////////////////////////////////////////

pub type DecodeResult<A> = Result<A, DecodeError>;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("CBOR decoder error: {0}")]
    Decoder(#[from] minicbor::decode::Error),
    #[error("ed25519 Signature error: {0}")]
    Signature(#[from] ed25519::Error),
    #[error("CBOR array length mismatch: {0}")]
    InvalidArrayLen(usize),
    #[error("Local identity changed")]
    LocalIdentityChanged(IdentityKey),
    #[error("Invalid type {0}: {1}")]
    InvalidType(u8, &'static str),
    #[error("Missing field: {0}")]
    MissingField(&'static str),
    #[error("Invalid field: ")]
    InvalidField(&'static str),
    #[error("Duplicate field: ")]
    DuplicateField(&'static str),
}
