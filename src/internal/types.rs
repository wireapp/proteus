// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor;
use internal::keys::IdentityKey;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::ops::Deref;

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

// Handle ///////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum Handle<'r, A: ?Sized + 'r> {
    Ref(&'r A),
    Own(A)
}

impl<'r, A: ?Sized + Clone> Handle<'r, A> {
    pub fn into_owned(self) -> A {
        match self {
            Handle::Ref(x) => x.clone(),
            Handle::Own(x) => x
        }
    }
}

impl<'r, A: ?Sized> Deref for Handle<'r, A> {
    type Target = A;

    fn deref(&self) -> &A {
        match *self {
            Handle::Ref(x)     => x,
            Handle::Own(ref x) => &x
        }
    }
}

impl<'r, A: ?Sized + Eq> Eq for Handle<'r, A> {}

impl<'r, A: ?Sized + PartialEq> PartialEq for Handle<'r, A> {
    #[inline]
    fn eq(&self, other: &Handle<'r, A>) -> bool {
        PartialEq::eq(&**self, &**other)
    }
}

impl<'r, A: ?Sized + Ord> Ord for Handle<'r, A> {
    #[inline]
    fn cmp(&self, other: &Handle<'r, A>) -> Ordering {
        Ord::cmp(&**self, &**other)
    }
}

impl<'r, A: ?Sized + PartialOrd> PartialOrd for Handle<'r, A> {
    #[inline]
    fn partial_cmp(&self, other: &Handle<'r, A>) -> Option<Ordering> {
        PartialOrd::partial_cmp(&**self, &**other)
    }
}
