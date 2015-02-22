// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use bincode::{EncoderWriter, EncodingError, DecoderReader, DecodingError};
use internal::util::{Array32, Array64};
use rustc_serialize::{Decodable, Encodable};
use sodiumoxide::crypto::scalarmult as ecdh;
use sodiumoxide::crypto::sign;
use std::io::{BufRead, Write};
use super::*;

// SecretKey ////////////////////////////////////////////////////////////////

pub fn enc_secret_key<W: Write>(k: &SecretKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    k.sec_edward.0.encode(e)
}

pub fn dec_secret_key<R: BufRead>(d: &mut DecoderReader<R>) -> Result<SecretKey, DecodingError> {
    Array64::decode(d).map(|v| {
        let ed = sign::SecretKey(v.array);
        let ck = ecdh::Scalar(from_ed25519_sk(&ed));
        SecretKey { sec_edward: ed, sec_curve: ck }
    })
}

// PublicKey ////////////////////////////////////////////////////////////////

pub fn enc_public_key<W: Write>(k: &PublicKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    k.pub_edward.0.encode(e)
}

pub fn dec_public_key<R: BufRead>(d: &mut DecoderReader<R>) -> Result<PublicKey, DecodingError> {
    Array32::decode(d).map(|v| {
        let ed = sign::PublicKey(v.array);
        let ck = ecdh::GroupElement(from_ed25519_pk(&ed));
        PublicKey { pub_edward: ed, pub_curve: ck }
    })
}

// Identity Key /////////////////////////////////////////////////////////////

pub fn enc_identity_key<W: Write>(k: &IdentityKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    enc_public_key(&k.public_key, e)
}

pub fn dec_identity_key<R: BufRead>(d: &mut DecoderReader<R>) -> Result<IdentityKey, DecodingError> {
    dec_public_key(d).map(|k| IdentityKey { public_key: k })
}

// Identity Keypair /////////////////////////////////////////////////////////

pub fn enc_identity_keypair<W: Write>(k: &IdentityKeyPair, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_secret_key(&k.secret_key, e));
    enc_identity_key(&k.public_key, e)
}

pub fn dec_identity_keypair<R: BufRead>(d: &mut DecoderReader<R>) -> Result<IdentityKeyPair, DecodingError> {
    let sk = try!(dec_secret_key(d));
    let pk = try!(dec_identity_key(d));
    Ok(IdentityKeyPair { secret_key: sk, public_key: pk })
}

// Prekey ID ////////////////////////////////////////////////////////////////

pub fn enc_prekey_id<W: Write>(k: &PreKeyId, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    k.0.encode(e)
}

pub fn dec_prekey_id<R: BufRead>(d: &mut DecoderReader<R>) -> Result<PreKeyId, DecodingError> {
    Decodable::decode(d).map(PreKeyId)
}

// Prekey ///////////////////////////////////////////////////////////////////

pub fn enc_prekey<W: Write>(k: &PreKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_prekey_id(&k.key_id, e));
    enc_keypair(&k.key_pair, e)
}

pub fn dec_prekey<R: BufRead>(d: &mut DecoderReader<R>) -> Result<PreKey, DecodingError> {
    let id = try!(dec_prekey_id(d));
    let kp = try!(dec_keypair(d));
    Ok(PreKey { key_id: id, key_pair: kp })
}

// Prekey Bundle ////////////////////////////////////////////////////////////

pub fn enc_prekey_bundle<W: Write>(k: &PreKeyBundle, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_prekey_id(&k.prekey_id, e));
    try!(enc_public_key(&k.public_key, e));
    enc_identity_key(&k.identity_key, e)
}

pub fn dec_prekey_bundle<R: BufRead>(d: &mut DecoderReader<R>) -> Result<PreKeyBundle, DecodingError> {
    let id = try!(dec_prekey_id(d));
    let pk = try!(dec_public_key(d));
    let ik = try!(dec_identity_key(d));
    Ok(PreKeyBundle { prekey_id: id, public_key: pk, identity_key: ik })
}

// Keypair //////////////////////////////////////////////////////////////////

pub fn enc_keypair<W: Write>(k: &KeyPair, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_secret_key(&k.secret_key, e));
    enc_public_key(&k.public_key, e)
}

pub fn dec_keypair<R: BufRead>(d: &mut DecoderReader<R>) -> Result<KeyPair, DecodingError> {
    let s = try!(dec_secret_key(d));
    let p = try!(dec_public_key(d));
    Ok(KeyPair { secret_key: s, public_key: p })
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use bincode::*;
    use internal::keys::KeyPair;
    use std::io::{BufRead, Write};
    use std::vec::Vec;
    use super::*;

    fn encoder<W: Write>(w: &mut W) -> EncoderWriter<W> {
        EncoderWriter::new(w)
    }

    fn decoder<R: BufRead>(b: &mut R) -> DecoderReader<R> {
        DecoderReader::new(b, SizeLimit::Infinite)
    }

    #[test]
    fn enc_dec_pubkey() {
        let k = KeyPair::new();
        let mut w = Vec::new();
        let b = match enc_public_key(&k.public_key, &mut encoder(&mut w)) {
            Err(e) => panic!("Failed to encode public key: {}", e),
            _      => w
        };
        match dec_public_key(&mut decoder(&mut b.as_slice())) {
            Err(e) => panic!("Failed to decode public key: {}", e),
            Ok(p)  => assert_eq!(k.public_key, p)
        }
    }

    #[test]
    fn enc_dec_seckey() {
        let k = KeyPair::new();
        let mut w = Vec::new();
        let b = match enc_secret_key(&k.secret_key, &mut encoder(&mut w)) {
            Err(e) => panic!("Failed to encode secret key: {}", e),
            _      => w
        };
        match dec_secret_key(&mut decoder(&mut b.as_slice())) {
            Err(e) => panic!("failed to decode secret key: {}", e),
            Ok(s)  => {
                assert_eq!(k.secret_key.sec_edward.0.as_slice(), s.sec_edward.0.as_slice());
                assert_eq!(k.secret_key.sec_curve.0.as_slice(), s.sec_curve.0.as_slice())
            }
        }
    }
}
