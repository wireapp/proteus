// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Decoder, Encoder};
use internal::util::{Bytes64, Bytes32, DecodeError, DecodeResult, EncodeResult};
use sodiumoxide::crypto::scalarmult as ecdh;
use sodiumoxide::crypto::sign;
use std::io::{Read, Write};
use super::*;

// SecretKey ////////////////////////////////////////////////////////////////

pub fn enc_secret_key<W: Write>(k: &SecretKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.bytes(&k.sec_edward.0).map_err(From::from)
}

pub fn dec_secret_key<R: Read>(d: &mut Decoder<R>) -> DecodeResult<SecretKey> {
    Bytes64::decode(d).map(|v| {
        let ed = sign::SecretKey(v.array);
        let ck = ecdh::Scalar(from_ed25519_sk(&ed));
        SecretKey { sec_edward: ed, sec_curve: ck }
    })
}

// PublicKey ////////////////////////////////////////////////////////////////

pub fn enc_public_key<W: Write>(k: &PublicKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.bytes(&k.pub_edward.0).map_err(From::from)
}

pub fn dec_public_key<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PublicKey> {
    Bytes32::decode(d).map(|v| {
        let ed = sign::PublicKey(v.array);
        let ck = ecdh::GroupElement(from_ed25519_pk(&ed));
        PublicKey { pub_edward: ed, pub_curve: ck }
    })
}

// Identity Key /////////////////////////////////////////////////////////////

pub fn enc_identity_key<W: Write>(k: &IdentityKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    enc_public_key(&k.public_key, e)
}

pub fn dec_identity_key<R: Read>(d: &mut Decoder<R>) -> DecodeResult<IdentityKey> {
    dec_public_key(d).map(|k| IdentityKey { public_key: k })
}

// Identity Version /////////////////////////////////////////////////////////

pub fn enc_identity_version<W: Write>(v: &IdentityVersion, e: &mut Encoder<W>) -> EncodeResult<()> {
    match *v {
        IdentityVersion::V1 => e.u16(1).map_err(From::from)
    }
}

pub fn dec_identity_version<R: Read>(d: &mut Decoder<R>) -> DecodeResult<IdentityVersion> {
    match try!(d.u16()) {
        1 => Ok(IdentityVersion::V1),
        v => Err(DecodeError::InvalidVersion(format!("unknow identity keypair version {}", v)))
    }
}

// Identity Keypair /////////////////////////////////////////////////////////

pub fn enc_identity_keypair<W: Write>(k: &IdentityKeyPair, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_identity_version(&k.version, e));
    try!(enc_secret_key(&k.secret_key, e));
    enc_identity_key(&k.public_key, e)
}

pub fn dec_identity_keypair<R: Read>(d: &mut Decoder<R>) -> DecodeResult<IdentityKeyPair> {
    let vs = try!(dec_identity_version(d));
    let sk = try!(dec_secret_key(d));
    let pk = try!(dec_identity_key(d));
    Ok(IdentityKeyPair { version: vs, secret_key: sk, public_key: pk })
}

// Prekey ID ////////////////////////////////////////////////////////////////

pub fn enc_prekey_id<W: Write>(k: &PreKeyId, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.u16(k.0).map_err(From::from)
}

pub fn dec_prekey_id<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKeyId> {
    d.u16().map(PreKeyId).map_err(From::from)
}

// Prekey Version //////////////////////////////////////////////////////////

pub fn enc_prekey_version<W: Write>(v: &PreKeyVersion, e: &mut Encoder<W>) -> EncodeResult<()> {
    match *v {
        PreKeyVersion::V1 => e.u16(1).map_err(From::from)
    }
}

pub fn dec_prekey_version<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKeyVersion> {
    match try!(d.u16()) {
        1 => Ok(PreKeyVersion::V1),
        v => Err(DecodeError::InvalidVersion(format!("unknow prekey version {}", v)))
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

pub fn enc_prekey<W: Write>(k: &PreKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_prekey_version(&k.version, e));
    try!(enc_prekey_id(&k.key_id, e));
    enc_keypair(&k.key_pair, e)
}

pub fn dec_prekey<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKey> {
    let vs = try!(dec_prekey_version(d));
    let id = try!(dec_prekey_id(d));
    let kp = try!(dec_keypair(d));
    Ok(PreKey { version: vs, key_id: id, key_pair: kp })
}

// Prekey Bundle ////////////////////////////////////////////////////////////

pub fn enc_prekey_bundle<W: Write>(k: &PreKeyBundle, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_prekey_id(&k.prekey_id, e));
    try!(enc_public_key(&k.public_key, e));
    enc_identity_key(&k.identity_key, e)
}

pub fn dec_prekey_bundle<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKeyBundle> {
    let id = try!(dec_prekey_id(d));
    let pk = try!(dec_public_key(d));
    let ik = try!(dec_identity_key(d));
    Ok(PreKeyBundle { prekey_id: id, public_key: pk, identity_key: ik })
}

// Keypair //////////////////////////////////////////////////////////////////

pub fn enc_keypair<W: Write>(k: &KeyPair, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_secret_key(&k.secret_key, e));
    enc_public_key(&k.public_key, e)
}

pub fn dec_keypair<R: Read>(d: &mut Decoder<R>) -> DecodeResult<KeyPair> {
    let s = try!(dec_secret_key(d));
    let p = try!(dec_public_key(d));
    Ok(KeyPair { secret_key: s, public_key: p })
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use internal::keys::KeyPair;
    use internal::util::roundtrip;
    use super::*;

    #[test]
    fn enc_dec_pubkey() {
        let k = KeyPair::new();
        let r = roundtrip(|mut e| enc_public_key(&k.public_key, &mut e),
                          |mut d| dec_public_key(&mut d));
        assert_eq!(k.public_key, r)
    }

    #[test]
    fn enc_dec_seckey() {
        let k = KeyPair::new();
        let r = roundtrip(|mut e| enc_secret_key(&k.secret_key, &mut e),
                          |mut d| dec_secret_key(&mut d));
        assert_eq!(&k.secret_key.sec_edward.0[..], &r.sec_edward.0[..]);
        assert_eq!(&k.secret_key.sec_curve.0[..], &r.sec_curve.0[..])
    }
}
