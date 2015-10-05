// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor;
use internal::keys::IdentityKey;
use std::error::Error;
use std::fmt;

// EncodeError //////////////////////////////////////////////////////////////

pub type EncodeResult<A> = Result<A, EncodeError>;

#[derive(Debug)]
pub enum EncodeError {
    Encoder(cbor::EncodeError)
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            EncodeError::Encoder(ref e) => write!(f, "CBOR encoder error: {}", e)
        }
    }
}

impl Error for EncodeError {
    fn description(&self) -> &str {
        "EncodeError"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            EncodeError::Encoder(ref e) => Some(e)
        }
    }
}

impl From<cbor::EncodeError> for EncodeError {
    fn from(err: cbor::EncodeError) -> EncodeError {
        EncodeError::Encoder(err)
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
