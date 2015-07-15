// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Decoder, Encoder};
use internal::util::{Bytes32, DecodeResult, EncodeResult};
use sodiumoxide::crypto::stream;
use sodiumoxide::crypto::auth::hmacsha256 as mac;
use std::io::{Read, Write};
use super::*;

// Cipher Key ///////////////////////////////////////////////////////////////

pub fn enc_cipher_key<W: Write>(k: &CipherKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.bytes(&k.key.0).map_err(From::from)
}

pub fn dec_cipher_key<R: Read>(d: &mut Decoder<R>) -> DecodeResult<CipherKey> {
    Bytes32::decode(d).map(|v| {
        CipherKey { key: stream::Key(v.array) }
    })
}

// MAC Key //////////////////////////////////////////////////////////////////

pub fn enc_mac_key<W: Write>(k: &MacKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.bytes(&k.key.0).map_err(From::from)
}

pub fn dec_mac_key<R: Read>(d: &mut Decoder<R>) -> DecodeResult<MacKey> {
    Bytes32::decode(d).map(|v| {
        MacKey { key: mac::Key(v.array) }
    })
}

// MAC //////////////////////////////////////////////////////////////////////

pub fn enc_mac<W: Write>(k: &Mac, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.bytes(&k.sig.0).map_err(From::from)
}

pub fn dec_mac<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Mac> {
    Bytes32::decode(d).map(|v| {
        Mac { sig: mac::Tag(v.array) }
    })
}

