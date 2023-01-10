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

use crate::internal::types::{DecodeError, DecodeResult};
use cbor::{self, Decoder};
use std::io::Read;

#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
use crate::internal::types::EncodeResult;

// Optional Values //////////////////////////////////////////////////////////

#[inline]
pub fn opt<A>(r: DecodeResult<A>) -> DecodeResult<Option<A>> {
    match r {
        Ok(x) => Ok(Some(x)),
        Err(DecodeError::Decoder(e)) => cbor::opt(Err(e)).map_err(From::from),
        Err(e) => Err(e),
    }
}

// Bytes32 //////////////////////////////////////////////////////////////////

pub struct Bytes32 {
    pub array: zeroize::Zeroizing<[u8; 32]>,
}

impl Bytes32 {
    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Bytes32> {
        let mut a = [0u8; 32];
        let n = d.read_bytes(&mut a)?;
        if 32 != n {
            return Err(DecodeError::InvalidArrayLen(n));
        }
        Ok(Bytes32 {
            array: zeroize::Zeroizing::new(a),
        })
    }
}

// Bytes64 //////////////////////////////////////////////////////////////////

pub struct Bytes64 {
    pub array: zeroize::Zeroizing<[u8; 64]>,
}

impl Bytes64 {
    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Bytes64> {
        let mut a = [0u8; 64];
        let n = d.read_bytes(&mut a)?;
        if 64 != n {
            return Err(DecodeError::InvalidArrayLen(n));
        }
        Ok(Bytes64 {
            array: zeroize::Zeroizing::new(a),
        })
    }
}

#[must_use]
pub fn fmt_hex(xs: &[u8]) -> String {
    hex::encode(xs)
}

// Test support /////////////////////////////////////////////////////////////

#[cfg(test)]
pub fn roundtrip<F, G, A>(enc: F, dec: G) -> A
where
    F: Fn(cbor::Encoder<&mut Cursor<Vec<u8>>>) -> EncodeResult<()>,
    G: Fn(cbor::Decoder<&mut Cursor<Vec<u8>>>) -> DecodeResult<A>,
{
    let mut rw = Cursor::new(Vec::new());
    match enc(cbor::Encoder::new(&mut rw)) {
        Ok(_) => (),
        Err(e) => panic!("encoder failure: {:?}", e),
    }
    rw.set_position(0);
    match dec(cbor::Decoder::new(cbor::Config::default(), &mut rw)) {
        Ok(x) => x,
        Err(e) => panic!("decoder failure: {:?}", e),
    }
}
