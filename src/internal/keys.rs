// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Config, Decoder, Encoder};
use cbor::skip::Skip;
use internal::ffi;
use internal::util::{Bytes64, Bytes32, DecodeError, DecodeResult, EncodeResult, fmt_hex};
use sodiumoxide::crypto::scalarmult as ecdh;
use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes;
use std::fmt::{Debug, Formatter, Error};
use std::io::{Cursor, Read, Write};
use std::u16;
use std::vec::Vec;

// Identity Key /////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct IdentityKey {
    pub public_key: PublicKey
}

impl IdentityKey {
    pub fn new(k: PublicKey) -> IdentityKey {
        IdentityKey { public_key: k }
    }

    pub fn fingerprint(&self) -> String {
        self.public_key.fingerprint()
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0)); self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKey> {
        let n = try!(d.object());
        let mut public_key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => public_key = Some(try!(PublicKey::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(IdentityKey {
            public_key: to_field!(public_key, "IdentityKey::public_key")
        })
    }
}

// Identity Keypair /////////////////////////////////////////////////////////

pub struct IdentityKeyPair {
    pub version:    u8,
    pub secret_key: SecretKey,
    pub public_key: IdentityKey
}

impl IdentityKeyPair {
    pub fn new() -> IdentityKeyPair {
        let k = KeyPair::new();
        IdentityKeyPair {
            version:    1,
            secret_key: k.secret_key,
            public_key: IdentityKey { public_key: k.public_key }
        }
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<IdentityKeyPair> {
        IdentityKeyPair::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(3));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.secret_key.encode(e));
        try!(e.u8(2)); self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKeyPair> {
        let n = try!(d.object());
        let mut version    = None;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version    = Some(try!(d.u8())),
                1 => secret_key = Some(try!(SecretKey::decode(d))),
                2 => public_key = Some(try!(IdentityKey::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(IdentityKeyPair {
            version:    to_field!(version, "IdentityKeyPair::version"),
            secret_key: to_field!(secret_key, "IdentityKeyPair::secret_key"),
            public_key: to_field!(public_key, "IdentityKeyPair::public_key")
        })
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct PreKey {
    pub version:  u8,
    pub key_id:   PreKeyId,
    pub key_pair: KeyPair
}

impl PreKey {
    pub fn new(i: PreKeyId) -> PreKey {
        PreKey {
            version: 1,
            key_id: i,
            key_pair: KeyPair::new()
        }
    }

    pub fn last_resort() -> PreKey {
        PreKey::new(MAX_PREKEY_ID)
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKey> {
        PreKey::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(3));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.key_id.encode(e));
        try!(e.u8(2)); self.key_pair.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKey> {
        let n = try!(d.object());
        let mut version  = None;
        let mut key_id   = None;
        let mut key_pair = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version  = Some(try!(d.u8())),
                1 => key_id   = Some(try!(PreKeyId::decode(d))),
                2 => key_pair = Some(try!(KeyPair::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(PreKey {
            version:  to_field!(version, "PreKey::version"),
            key_id:   to_field!(key_id, "PreKey::key_id"),
            key_pair: to_field!(key_pair, "PreKey::key_pair")
        })
    }
}

pub fn gen_prekeys(start: PreKeyId, size: u16) -> Vec<PreKey> {
    (1 ..).map(|i| ((start.value() as u32 + i) % (MAX_PREKEY_ID.value() as u32)))
          .map(|i| PreKey::new(PreKeyId::new(i as u16)))
          .take(size as usize)
          .collect()
}

// Prekey bundle ////////////////////////////////////////////////////////////

#[derive(PartialEq, Eq, Debug)]
pub struct PreKeyBundle {
    pub version:      u8,
    pub prekey_id:    PreKeyId,
    pub public_key:   PublicKey,
    pub identity_key: IdentityKey
}

impl PreKeyBundle {
    pub fn new(ident: IdentityKey, key: &PreKey) -> PreKeyBundle {
        PreKeyBundle {
            version:      1,
            prekey_id:    key.key_id,
            public_key:   key.key_pair.public_key,
            identity_key: ident
        }
    }
    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKeyBundle> {
        PreKeyBundle::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(4));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.prekey_id.encode(e));
        try!(e.u8(2)); try!(self.public_key.encode(e));
        try!(e.u8(3)); self.identity_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKeyBundle> {
        let n = try!(d.object());
        let mut version      = None;
        let mut prekey_id    = None;
        let mut public_key   = None;
        let mut identity_key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version      = Some(try!(d.u8())),
                1 => prekey_id    = Some(try!(PreKeyId::decode(d))),
                2 => public_key   = Some(try!(PublicKey::decode(d))),
                3 => identity_key = Some(try!(IdentityKey::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(PreKeyBundle {
            version:      to_field!(version, "PreKeyBundle::version"),
            prekey_id:    to_field!(prekey_id, "PreKeyBundle::prekey_id"),
            public_key:   to_field!(public_key, "PreKeyBundle::public_key"),
            identity_key: to_field!(identity_key, "PreKeyBundle::identity_key")
        })
    }
}

// Prekey ID ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PreKeyId(u16);

pub const MAX_PREKEY_ID: PreKeyId = PreKeyId(u16::MAX);

impl PreKeyId {
    pub fn new(i: u16) -> PreKeyId {
        PreKeyId(i)
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.u16(self.0).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKeyId> {
        d.u16().map(PreKeyId).map_err(From::from)
    }
}

// Keypair //////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey
}

impl KeyPair {
    pub fn new() -> KeyPair {
        let (p, s) = sign::gen_keypair();

        let es = from_ed25519_sk(&s);
        let ep = from_ed25519_pk(&p);

        KeyPair {
            secret_key: SecretKey {
                sec_edward: s,
                sec_curve:  ecdh::Scalar(es)
            },
            public_key: PublicKey {
                pub_edward: p,
                pub_curve:  ecdh::GroupElement(ep)
            }
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(2));
        try!(e.u8(0)); try!(self.secret_key.encode(e));
        try!(e.u8(1)); self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<KeyPair> {
        let n = try!(d.object());
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => secret_key = Some(try!(SecretKey::decode(d))),
                1 => public_key = Some(try!(PublicKey::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(KeyPair {
            secret_key: to_field!(secret_key, "KeyPair::secret_key"),
            public_key: to_field!(public_key, "KeyPair::public_key")
        })
    }
}

// SecretKey ////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct SecretKey {
    sec_edward: sign::SecretKey,
    sec_curve:  ecdh::Scalar
}

impl SecretKey {
    pub fn sign(&self, m: &[u8]) -> Signature {
        Signature { sig: sign::sign_detached(m, &self.sec_edward) }
    }

    pub fn shared_secret(&self, p: &PublicKey) -> [u8; 32] {
        let ecdh::GroupElement(b) = ecdh::scalarmult(&self.sec_curve, &p.pub_curve);
        b
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.sec_edward.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<SecretKey> {
        let n = try!(d.object());
        let mut sec_edward = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => sec_edward = Some(try!(Bytes64::decode(d).map(|v| sign::SecretKey(v.array)))),
                _ => try!(d.skip())
            }
        }
        let sec_curve = sec_edward.as_ref().map(|ed| ecdh::Scalar(from_ed25519_sk(ed)));
        Ok(SecretKey {
            sec_edward: to_field!(sec_edward, "SecretKey::sec_edward"),
            sec_curve:  to_field!(sec_curve, "SecretKey::sec_curve")
        })
    }
}

// PublicKey ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone)]
pub struct PublicKey {
    pub_edward: sign::PublicKey,
    pub_curve:  ecdh::GroupElement
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        &self.pub_edward.0 == &other.pub_edward.0
            &&
        &self.pub_curve.0 == &other.pub_curve.0
    }
}

impl Eq for PublicKey {}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:?}", &self.pub_edward.0)
    }
}

impl PublicKey {
    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        sign::verify_detached(&s.sig, m, &self.pub_edward)
    }

    pub fn fingerprint(&self) -> String {
        fmt_hex(&self.pub_edward.0)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.pub_edward.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PublicKey> {
        let n = try!(d.object());
        let mut pub_edward = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => pub_edward = Some(try!(Bytes32::decode(d).map(|v| sign::PublicKey(v.array)))),
                _ => try!(d.skip())
            }
        }
        let pub_curve = pub_edward.as_ref().map(|ed| ecdh::GroupElement(from_ed25519_pk(ed)));
        Ok(PublicKey {
            pub_edward: to_field!(pub_edward, "PublicKey::pub_edward"),
            pub_curve:  to_field!(pub_curve, "PublicKey::pub_curve")
        })
    }
}

// Random ///////////////////////////////////////////////////////////////////

pub fn rand_bytes(size: usize) -> Vec<u8> {
    randombytes::randombytes(size)
}

// Signature ////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct Signature {
    sig: sign::Signature
}

// Internal /////////////////////////////////////////////////////////////////

pub fn from_ed25519_pk(k: &sign::PublicKey) -> [u8; ecdh::BYTES] {
    let mut ep = [0u8; ecdh::BYTES];
    unsafe {
        ffi::crypto_sign_ed25519_pk_to_curve25519(ep.as_mut_ptr(), (&k.0).as_ptr());
    }
    ep
}

pub fn from_ed25519_sk(k: &sign::SecretKey) -> [u8; ecdh::SCALARBYTES] {
    let mut es = [0u8; ecdh::SCALARBYTES];
    unsafe {
        ffi::crypto_sign_ed25519_sk_to_curve25519(es.as_mut_ptr(), (&k.0).as_ptr());
    }
    es
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use internal::util::roundtrip;
    use super::*;

    #[test]
    fn prekey_generation() {
        let k = gen_prekeys(PreKeyId::new(0xFFFC), 5)
                .iter()
                .map(|k| k.key_id.value())
                .collect::<Vec<_>>();
        assert_eq!(vec![0xFFFD, 0xFFFE, 0, 1, 2], k)
    }

    #[test]
    fn dh_agreement() {
        let a  = KeyPair::new();
        let b  = KeyPair::new();
        let sa = a.secret_key.shared_secret(&b.public_key);
        let sb = b.secret_key.shared_secret(&a.public_key);
        assert_eq!(&sa, &sb)
    }

    #[test]
    fn sign_and_verify() {
        let a = KeyPair::new();
        let s = a.secret_key.sign(b"foobarbaz");
        assert!(a.public_key.verify(&s, b"foobarbaz"));
        assert!(!a.public_key.verify(&s, b"foobar"));
    }

    #[test]
    fn enc_dec_pubkey() {
        let k = KeyPair::new();
        let r = roundtrip(|mut e| k.public_key.encode(&mut e), |mut d| PublicKey::decode(&mut d));
        assert_eq!(k.public_key, r)
    }

    #[test]
    fn enc_dec_seckey() {
        let k = KeyPair::new();
        let r = roundtrip(|mut e| k.secret_key.encode(&mut e), |mut d| SecretKey::decode(&mut d));
        assert_eq!(&k.secret_key.sec_edward.0[..], &r.sec_edward.0[..]);
        assert_eq!(&k.secret_key.sec_curve.0[..], &r.sec_curve.0[..])
    }
}
