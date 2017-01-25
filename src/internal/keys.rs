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

use cbor::{Config, Decoder, Encoder};
use cbor::skip::Skip;
use internal::ffi;
use internal::types::{DecodeError, DecodeResult, EncodeResult};
use internal::util::{Bytes64, Bytes32, fmt_hex, opt};
use libsodium_sys::{self as libsodium};
use sodiumoxide::crypto::scalarmult as ecdh;
use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes;
use std::fmt::{self, Debug, Formatter, Error};
use std::io::{Cursor, Read, Write};
use std::u16;
use std::vec::Vec;

// Identity Key /////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
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

#[derive(Clone)]
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PreKeyAuth {
    Invalid,
    Valid,
    Unknown
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreKeyBundle {
    pub version:      u8,
    pub prekey_id:    PreKeyId,
    pub public_key:   PublicKey,
    pub identity_key: IdentityKey,
    pub signature:    Option<Signature>
}

impl PreKeyBundle {
    pub fn new(ident: IdentityKey, key: &PreKey) -> PreKeyBundle {
        PreKeyBundle {
            version:      1,
            prekey_id:    key.key_id,
            public_key:   key.key_pair.public_key.clone(),
            identity_key: ident,
            signature:    None
        }
    }

    pub fn signed(ident: &IdentityKeyPair, key: &PreKey) -> PreKeyBundle {
        let ratchet_key = key.key_pair.public_key.clone();
        let signature   = ident.secret_key.sign(&ratchet_key.pub_edward.0);
        PreKeyBundle {
            version:      1,
            prekey_id:    key.key_id,
            public_key:   ratchet_key,
            identity_key: ident.public_key.clone(),
            signature:    Some(signature)
        }
    }

    pub fn verify(&self) -> PreKeyAuth {
        match self.signature {
            Some(ref sig) =>
                if self.identity_key.public_key.verify(sig, &self.public_key.pub_edward.0) {
                    PreKeyAuth::Valid
                } else {
                    PreKeyAuth::Invalid
                },
            None => PreKeyAuth::Unknown
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
        try!(e.object(5));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.prekey_id.encode(e));
        try!(e.u8(2)); try!(self.public_key.encode(e));
        try!(e.u8(3)); try!(self.identity_key.encode(e));
        try!(e.u8(4)); match self.signature {
            Some(ref sig) => sig.encode(e),
            None          => e.null().map_err(From::from)
        }
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKeyBundle> {
        let n = try!(d.object());
        let mut version      = None;
        let mut prekey_id    = None;
        let mut public_key   = None;
        let mut identity_key = None;
        let mut signature    = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version      = Some(try!(d.u8())),
                1 => prekey_id    = Some(try!(PreKeyId::decode(d))),
                2 => public_key   = Some(try!(PublicKey::decode(d))),
                3 => identity_key = Some(try!(IdentityKey::decode(d))),
                4 => signature    = try!(opt(Signature::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(PreKeyBundle {
            version:      to_field!(version, "PreKeyBundle::version"),
            prekey_id:    to_field!(prekey_id, "PreKeyBundle::prekey_id"),
            public_key:   to_field!(public_key, "PreKeyBundle::public_key"),
            identity_key: to_field!(identity_key, "PreKeyBundle::identity_key"),
            signature:    signature
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

impl fmt::Display for PreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
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

        let es = from_ed25519_sk(&s).expect("invalid ed25519 secret key");
        let ep = from_ed25519_pk(&p).expect("invalid ed25519 public key");

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Zero();

// Sodiumoxide's scalarmult function ignores the return code of
// `crypto_scalarmult_curve25519`, hence we call that function directly.
// `crypto_scalarmult_curve25519` returns -1 if the resulting value is all 0.
fn scalarmult(s: &ecdh::Scalar, g: &ecdh::GroupElement) -> Result<ecdh::GroupElement, Zero> {
    let mut ge = [0; ecdh::GROUPELEMENTBYTES];
    unsafe {
        if libsodium::crypto_scalarmult_curve25519(&mut ge, &s.0, &g.0) != 0 {
            Err(Zero())
        } else {
            Ok(ecdh::GroupElement(ge))
        }
    }
}

#[derive(Clone)]
pub struct SecretKey {
    sec_edward: sign::SecretKey,
    sec_curve:  ecdh::Scalar
}

impl SecretKey {
    pub fn sign(&self, m: &[u8]) -> Signature {
        Signature { sig: sign::sign_detached(m, &self.sec_edward) }
    }

    pub fn shared_secret(&self, p: &PublicKey) -> Result<[u8; 32], Zero> {
        scalarmult(&self.sec_curve, &p.pub_curve).map(|ge| ge.0)
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
        let sec_edward = sec_edward.ok_or(DecodeError::MissingField("SecretKey::sec_edward"))?;
        let sec_curve  = from_ed25519_sk(&sec_edward)
            .map(ecdh::Scalar)
            .map_err(|()| DecodeError::InvalidField("SecretKey::sec_edward"))?;
        Ok(SecretKey {
            sec_edward: sec_edward,
            sec_curve:  sec_curve
        })
    }
}

// PublicKey ////////////////////////////////////////////////////////////////

#[derive(Clone)]
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
        let pub_edward = pub_edward.ok_or(DecodeError::MissingField("PublicKey::pub_edward"))?;
        let pub_curve  = from_ed25519_pk(&pub_edward)
            .map(ecdh::GroupElement)
            .map_err(|()| DecodeError::InvalidField("PublicKey::pub_edward"))?;
        Ok(PublicKey {
            pub_edward: pub_edward,
            pub_curve:  pub_curve
        })
    }
}

// Random ///////////////////////////////////////////////////////////////////

pub fn rand_bytes(size: usize) -> Vec<u8> {
    randombytes::randombytes(size)
}

// Signature ////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    sig: sign::Signature
}

impl Signature {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.sig.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Signature> {
        let n = try!(d.object());
        let mut sig = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => sig = Some(try!(Bytes64::decode(d).map(|v| sign::Signature(v.array)))),
                _ => try!(d.skip())
            }
        }
        Ok(Signature {
            sig: to_field!(sig, "Signature::sig")
        })
    }
}

// Internal /////////////////////////////////////////////////////////////////

pub fn from_ed25519_pk(k: &sign::PublicKey) -> Result<[u8; ecdh::GROUPELEMENTBYTES], ()> {
    let mut ep = [0u8; ecdh::GROUPELEMENTBYTES];
    unsafe {
        if ffi::crypto_sign_ed25519_pk_to_curve25519(ep.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
            Ok(ep)
        } else {
            Err(())
        }
    }
}

pub fn from_ed25519_sk(k: &sign::SecretKey) -> Result<[u8; ecdh::SCALARBYTES], ()> {
    let mut es = [0u8; ecdh::SCALARBYTES];
    unsafe {
        if ffi::crypto_sign_ed25519_sk_to_curve25519(es.as_mut_ptr(), (&k.0).as_ptr()) == 0 {
            Ok(es)
        } else {
            Err(())
        }
    }
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

    #[test]
    fn enc_dec_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::new(i.public_key, &k);
        let r = roundtrip(|mut e| b.encode(&mut e), |mut d| PreKeyBundle::decode(&mut d));
        assert_eq!(None, b.signature);
        assert_eq!(b, r);
    }

    #[test]
    fn enc_dec_signed_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::signed(&i, &k);
        let r = roundtrip(|mut e| b.encode(&mut e), |mut d| PreKeyBundle::decode(&mut d));
        assert_eq!(b, r);
        assert_eq!(PreKeyAuth::Valid, b.verify());
        assert_eq!(PreKeyAuth::Valid, r.verify());
    }

    #[test]
    fn degenerated_key() {
        let mut k = KeyPair::new();
        for i in 0 .. k.public_key.pub_curve.0.len() {
            k.public_key.pub_curve.0[i] = 0
        }
        assert_eq!(Err(Zero()), k.secret_key.shared_secret(&k.public_key))
    }
}
