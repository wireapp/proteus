// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use bincode::{EncoderWriter, EncodingError, DecoderReader, DecodingError};
use internal::util::Array32;
use rustc_serialize::{Encodable};
use sodiumoxide::crypto::stream;
use sodiumoxide::crypto::auth::hmacsha256 as mac;
use super::*;

// Cipher Key ///////////////////////////////////////////////////////////////

pub fn enc_cipher_key<W: Writer>(k: &CipherKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    k.key.0.encode(e)
}

pub fn dec_cipher_key<R: Buffer>(d: &mut DecoderReader<R>) -> Result<CipherKey, DecodingError> {
    Array32::decode(d).map(|v| {
        CipherKey { key: stream::Key(v.array) }
    })
}

// MAC Key //////////////////////////////////////////////////////////////////

pub fn enc_mac_key<W: Writer>(k: &MacKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    k.key.0.encode(e)
}

pub fn dec_mac_key<R: Buffer>(d: &mut DecoderReader<R>) -> Result<MacKey, DecodingError> {
    Array32::decode(d).map(|v| {
        MacKey { key: mac::Key(v.array) }
    })
}

// MAC //////////////////////////////////////////////////////////////////////

pub fn enc_mac<W: Writer>(k: &Mac, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    k.sig.0.encode(e)
}

pub fn dec_mac<R: Buffer>(d: &mut DecoderReader<R>) -> Result<Mac, DecodingError> {
    Array32::decode(d).map(|v| {
        Mac { sig: mac::Tag(v.array) }
    })
}
