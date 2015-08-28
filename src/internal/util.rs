// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{self, Decoder};
use internal::keys::IdentityKey;
use std::error::Error;
use std::fmt;
use std::io::Read;

#[cfg(test)]
use std::io::Cursor;

macro_rules! to_field {
    ($test: expr, $msg: expr) => (match $test {
        Some(val) => val,
        None      => return Err(DecodeError::MissingField($msg))
    })
}

pub type EncodeResult<A> = Result<A, EncodeError>;
pub type DecodeResult<A> = Result<A, DecodeError>;

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

#[derive(Debug)]
pub enum DecodeError {
    Decoder(cbor::DecodeError),
    InvalidArrayLen(usize),
    LocalIdentityChanged(IdentityKey),
    InvalidMessage(String),
    MissingField(&'static str)
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            DecodeError::Decoder(ref e)          => write!(f, "CBOR decoder error: {}", e),
            DecodeError::InvalidArrayLen(n)      => write!(f, "CBOR array length mismatch: {}", n),
            DecodeError::LocalIdentityChanged(_) => write!(f, "Local identity changed"),
            DecodeError::InvalidMessage(ref s)   => write!(f, "Invalid message: {}", s),
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

// Bytes32 //////////////////////////////////////////////////////////////////

pub struct Bytes32 { pub array: [u8; 32] }

impl Bytes32 {
    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Bytes32> {
        let v = try!(d.bytes());
        if 32 != v.len() {
            return Err(DecodeError::InvalidArrayLen(v.len()))
        }
        let mut a = [0u8; 32];
        for i in 0..32 {
            a[i] = v[i]
        }
        Ok(Bytes32 { array: a })
    }
}

// Bytes64 //////////////////////////////////////////////////////////////////

pub struct Bytes64 { pub array: [u8; 64] }

impl Bytes64 {
    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Bytes64> {
        let v = try!(d.bytes());
        if 64 != v.len() {
            return Err(DecodeError::InvalidArrayLen(v.len()))
        }
        let mut a = [0u8; 64];
        for i in 0..64 {
            a[i] = v[i]
        }
        Ok(Bytes64 { array: a })
    }
}

// Hex formatting ///////////////////////////////////////////////////////////

const HEX_DIGITS: &'static [u8] = b"0123456789abcdef";

pub fn fmt_hex(xs: &[u8]) -> String {
    let mut v = Vec::with_capacity(xs.len() * 2);
    for x in xs {
        v.push(HEX_DIGITS[(x >> 4) as usize]);
        v.push(HEX_DIGITS[(x & 0xf) as usize])
    }
    unsafe {
        String::from_utf8_unchecked(v)
    }
}

// Test support /////////////////////////////////////////////////////////////

#[cfg(test)]
pub fn roundtrip<F, G, A>(enc: F, dec: G) -> A
where F: Fn(cbor::Encoder<&mut Cursor<Vec<u8>>>) -> EncodeResult<()>,
      G: Fn(cbor::Decoder<&mut Cursor<Vec<u8>>>) -> DecodeResult<A>
{
    let mut rw = Cursor::new(Vec::new());
    match enc(cbor::Encoder::new(&mut rw)) {
        Ok(_)  => (),
        Err(e) => panic!("encoder failure: {:?}", e)
    }
    rw.set_position(0);
    match dec(cbor::Decoder::new(cbor::Config::default(), &mut rw)) {
        Ok(x)  => x,
        Err(e) => panic!("decoder failure: {:?}", e)
    }
}
