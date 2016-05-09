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

use cbor;
use internal::keys::IdentityKey;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum InternalError {
    NoSessionForTag
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            InternalError::NoSessionForTag => write!(f, "No session found for session tag.")
        }
    }
}

impl Error for InternalError {
    fn description(&self) -> &str {
        "InternalError"
    }
}

// EncodeError //////////////////////////////////////////////////////////////

pub type EncodeResult<A> = Result<A, EncodeError>;

#[derive(Debug)]
pub enum EncodeError {
    Internal(InternalError),
    Encoder(cbor::EncodeError)
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            EncodeError::Internal(ref e) => write!(f, "Internal error: {}", e),
            EncodeError::Encoder(ref e)  => write!(f, "CBOR encoder error: {}", e)
        }
    }
}

impl Error for EncodeError {
    fn description(&self) -> &str {
        "EncodeError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            EncodeError::Internal(ref e) => Some(e),
            EncodeError::Encoder(ref e)  => Some(e),
        }
    }
}

impl From<cbor::EncodeError> for EncodeError {
    fn from(err: cbor::EncodeError) -> EncodeError {
        EncodeError::Encoder(err)
    }
}

impl From<InternalError> for EncodeError {
    fn from(err: InternalError) -> EncodeError {
        EncodeError::Internal(err)
    }
}

// DecodeError //////////////////////////////////////////////////////////////

pub type DecodeResult<A> = Result<A, DecodeError>;

#[derive(Debug)]
pub enum DecodeError {
    Decoder(cbor::DecodeError),
    InvalidArrayLen(usize),
    LocalIdentityChanged(IdentityKey),
    InvalidType(u8, &'static str),
    MissingField(&'static str)
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            DecodeError::Decoder(ref e)          => write!(f, "CBOR decoder error: {}", e),
            DecodeError::InvalidArrayLen(n)      => write!(f, "CBOR array length mismatch: {}", n),
            DecodeError::LocalIdentityChanged(_) => write!(f, "Local identity changed"),
            DecodeError::InvalidType(t, ref s)   => write!(f, "Invalid type {}: {}", t, s),
            DecodeError::MissingField(ref s)     => write!(f, "Missing field: {}", s)
        }
    }
}

impl Error for DecodeError {
    fn description(&self) -> &str {
        "DecodeError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            DecodeError::Decoder(ref e) => Some(e),
            _                           => None
        }
    }
}

impl From<cbor::DecodeError> for DecodeError {
    fn from(err: cbor::DecodeError) -> DecodeError {
        DecodeError::Decoder(err)
    }
}
