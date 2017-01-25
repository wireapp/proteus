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

use cbor::{self, Decoder};
use internal::types::{DecodeError, DecodeResult};
use std::io::Read;

#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
use internal::types::EncodeResult;

macro_rules! to_field {
    ($test: expr, $msg: expr) => {
        match $test {
            Some(val) => val,
            None      => return Err(DecodeError::MissingField($msg))
        }
    }
}

macro_rules! uniq {
    ($msg: expr, $name: ident, $action: expr) => {
        if $name.is_some() {
            return Err(DecodeError::DuplicateField($msg))
        } else {
            $name = Some($action)
        }
    }
}

// Optional Values //////////////////////////////////////////////////////////

pub fn opt<A>(r: DecodeResult<A>) -> DecodeResult<Option<A>> {
    match r {
        Ok(x)  => Ok(Some(x)),
        Err(DecodeError::Decoder(e)) => cbor::opt(Err(e)).map_err(From::from),
        Err(e) => Err(e)
    }
}

// Bytes32 //////////////////////////////////////////////////////////////////

pub struct Bytes32 { pub array: [u8; 32] }

impl Bytes32 {
    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Bytes32> {
        let v = d.bytes()?;
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
        let v = d.bytes()?;
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
