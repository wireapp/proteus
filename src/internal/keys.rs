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

use cbor::skip::Skip;
use cbor::{Config, Decoder, Encoder};
use internal::ffi;
use internal::types::{DecodeError, DecodeResult, EncodeResult};
use internal::util::{fmt_hex, opt, Bytes32, Bytes64};
use sodiumoxide::crypto::scalarmult as ecdh;
use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes;
use std::fmt::{self, Debug};
use std::io::{Cursor, Read, Write};
use std::u16;
use std::vec::Vec;

// Identity Key /////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityKey {
    pub public_key: IdentityPublicKey,
}

impl IdentityKey {
    pub fn new(k: IdentityPublicKey) -> IdentityKey {
        IdentityKey { public_key: k }
    }

    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        self.public_key.verify(s, m)
    }

    pub fn fingerprint(&self) -> String {
        self.public_key.fingerprint()
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKey> {
        let n = d.object()?;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "IdentityPublicKey::public_key",
                    public_key,
                    IdentityPublicKey::decode(d)?
                ),
                _ => d.skip()?,
            }
        }
        Ok(IdentityKey {
            public_key: to_field!(public_key, "IdentityPublicKey::public_key"),
        })
    }
}

// Identity Keypair /////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct IdentityKeyPair {
    pub version: u8,
    pub secret_key: IdentitySecretKey,
    pub public_key: IdentityKey,
}

impl Default for IdentityKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityKeyPair {
    pub fn new() -> IdentityKeyPair {
        let (public_edward, secret_edward) = sign::gen_keypair();

        let es = from_ed25519_sk(&secret_edward).expect("invalid ed25519 secret key");
        let ep = from_ed25519_pk(&public_edward).expect("invalid ed25519 public key");

        let secret_key = IdentitySecretKey {
            sec_edward: secret_edward,
            sec_curve: ecdh::Scalar(es),
        };
        let public_key = IdentityKey::new(IdentityPublicKey {
            pub_edward: public_edward,
            pub_curve: ecdh::GroupElement(ep),
        });

        IdentityKeyPair {
            version: 2,
            secret_key,
            public_key,
        }
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<IdentityKeyPair> {
        IdentityKeyPair::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        let version = 2;
        e.object(3)?;
        e.u8(0)?;
        e.u8(version)?;
        e.u8(3)?;
        self.secret_key.encode(e)?;
        e.u8(4)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKeyPair> {
        let n = d.object()?;
        let mut version_option = None;
        let mut secret_key_v1_option = None;
        let mut public_key_v1_option = None;
        let mut secret_key_v2_option = None;
        let mut public_key_v2_option = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("IdentityKeyPair::version", version_option, d.u8()?),
                1 => uniq!(
                    "IdentityKeyPair::secret_key_v1",
                    secret_key_v1_option,
                    IdentitySecretKey::decode(d)?
                ),
                2 => uniq!(
                    "IdentityKeyPair::public_key_v1",
                    public_key_v1_option,
                    IdentityKey::decode(d)?
                ),
                3 => uniq!(
                    "IdentityKeyPair::secret_key_v2",
                    secret_key_v2_option,
                    IdentitySecretKey::decode(d)?
                ),
                4 => uniq!(
                    "IdentityKeyPair::public_key_v2",
                    public_key_v2_option,
                    IdentityKey::decode(d)?
                ),
                _ => d.skip()?,
            }
        }
        let version = to_field!(version_option, "IdentityKeyPair::version");
        match version {
            1 => Ok(IdentityKeyPair {
                version,
                secret_key: to_field!(secret_key_v1_option, "IdentityKeyPair::secret_key_v2"),
                public_key: to_field!(public_key_v1_option, "IdentityKeyPair::public_key_v2"),
            }),
            2 => Ok(IdentityKeyPair {
                version,
                secret_key: to_field!(secret_key_v2_option, "IdentityKeyPair::secret_key_v2"),
                public_key: to_field!(public_key_v2_option, "IdentityKeyPair::public_key_v2"),
            }),
            _ => Err(DecodeError::InvalidField("IdentitySecretKey::sec_curve")),
        }
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

#[derive(PartialEq, Debug, Clone)]
pub struct PreKey {
    pub version: u8,
    pub key_id: PreKeyId,
    pub key_pair: DHKeyPair,
}

impl PreKey {
    pub fn new(i: PreKeyId) -> PreKey {
        PreKey {
            version: 1,
            key_id: i,
            key_pair: DHKeyPair::new(),
        }
    }

    pub fn last_resort() -> PreKey {
        PreKey::new(MAX_PREKEY_ID)
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKey> {
        PreKey::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(3)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.key_id.encode(e)?;
        e.u8(2)?;
        self.key_pair.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKey> {
        let n = d.object()?;
        let mut version = None;
        let mut key_id = None;
        let mut key_pair = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("PreKey::version", version, d.u8()?),
                1 => uniq!("PreKey::key_id", key_id, PreKeyId::decode(d)?),
                2 => uniq!("PreKey::key_pair", key_pair, DHKeyPair::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(PreKey {
            version: to_field!(version, "PreKey::version"),
            key_id: to_field!(key_id, "PreKey::key_id"),
            key_pair: to_field!(key_pair, "PreKey::key_pair"),
        })
    }
}

pub fn gen_prekeys(start: PreKeyId, size: u16) -> Vec<PreKey> {
    (1..)
        .map(|i| ((u32::from(start.value()) + i) % u32::from(MAX_PREKEY_ID.value())))
        .map(|i| PreKey::new(PreKeyId::new(i as u16)))
        .take(size as usize)
        .collect()
}

// Prekey bundle ////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PreKeyAuth {
    Invalid,
    Valid,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreKeyBundle {
    pub version: u8,
    pub prekey_id: PreKeyId,
    pub public_key: DHPublicKey,
    pub identity_key: IdentityKey,
    pub signature: Option<Signature>,
}

impl PreKeyBundle {
    pub fn new(ident: IdentityKey, key: &PreKey) -> PreKeyBundle {
        PreKeyBundle {
            version: 1,
            prekey_id: key.key_id,
            public_key: key.key_pair.public_key.clone(),
            identity_key: ident,
            signature: None,
        }
    }

    pub fn signed(ident: &IdentityKeyPair, key: &PreKey) -> PreKeyBundle {
        let ratchet_key = key.key_pair.public_key.clone();
        let signature = ident.secret_key.sign(&ratchet_key.pub_curve.0);
        PreKeyBundle {
            version: 1,
            prekey_id: key.key_id,
            public_key: ratchet_key,
            identity_key: ident.public_key.clone(),
            signature: Some(signature),
        }
    }

    pub fn verify(&self) -> PreKeyAuth {
        match self.signature {
            Some(ref sig) => {
                if self
                    .identity_key
                    .public_key
                    .verify(sig, &self.public_key.pub_curve.0)
                {
                    PreKeyAuth::Valid
                } else {
                    PreKeyAuth::Invalid
                }
            }
            None => PreKeyAuth::Unknown,
        }
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<PreKeyBundle> {
        PreKeyBundle::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(5)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.prekey_id.encode(e)?;
        e.u8(2)?;
        self.public_key.encode(e)?;
        e.u8(3)?;
        self.identity_key.encode(e)?;
        e.u8(4)?;
        match self.signature {
            Some(ref sig) => sig.encode(e),
            None => e.null().map_err(From::from),
        }
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKeyBundle> {
        let n = d.object()?;
        let mut version = None;
        let mut prekey_id = None;
        let mut public_key = None;
        let mut identity_key = None;
        let mut signature = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("PreKeyBundle::version", version, d.u8()?),
                1 => uniq!("PreKeyBundle::prekey_id", prekey_id, PreKeyId::decode(d)?),
                2 => uniq!(
                    "PreKeyBundle::public_key",
                    public_key,
                    DHPublicKey::decode(d)?
                ),
                3 => uniq!(
                    "PreKeyBundle::identity_key",
                    identity_key,
                    IdentityKey::decode(d)?
                ),
                4 => uniq!(
                    "PreKeyBundle::signature",
                    signature,
                    opt(Signature::decode(d))?
                ),
                _ => d.skip()?,
            }
        }
        Ok(PreKeyBundle {
            version: to_field!(version, "PreKeyBundle::version"),
            prekey_id: to_field!(prekey_id, "PreKeyBundle::prekey_id"),
            public_key: to_field!(public_key, "PreKeyBundle::public_key"),
            identity_key: to_field!(identity_key, "PreKeyBundle::identity_key"),
            signature: signature.unwrap_or(None),
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

    pub fn value(self) -> u16 {
        self.0
    }

    pub fn encode<W: Write>(self, e: &mut Encoder<W>) -> EncodeResult<()> {
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

// DHKeypair //////////////////////////////////////////////////////////////////

#[derive(PartialEq, Debug, Clone)]
pub struct DHKeyPair {
    pub secret_key: DHSecretKey,
    pub public_key: DHPublicKey,
}

impl Default for DHKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl DHKeyPair {
    pub fn new() -> DHKeyPair {
        let random_bytes = rand_bytes(ecdh::SCALARBYTES);
        let mut private_key = ecdh::Scalar([0u8; ecdh::SCALARBYTES]);
        private_key.0[..ecdh::SCALARBYTES].clone_from_slice(&random_bytes[..ecdh::SCALARBYTES]);
        let public_key = ecdh::scalarmult_base(&private_key);

        DHKeyPair {
            secret_key: DHSecretKey {
                sec_curve: private_key,
            },
            public_key: DHPublicKey {
                pub_curve: public_key,
            },
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0)?;
        self.secret_key.encode(e)?;
        e.u8(1)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<DHKeyPair> {
        let n = d.object()?;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("KeyPair::secret_key", secret_key, DHSecretKey::decode(d)?),
                1 => uniq!("KeyPair::public_key", public_key, DHPublicKey::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(DHKeyPair {
            secret_key: to_field!(secret_key, "KeyPair::secret_key"),
            public_key: to_field!(public_key, "KeyPair::public_key"),
        })
    }
}

// IdentitySecretKey ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Zero {}

#[derive(Clone)]
pub struct IdentitySecretKey {
    pub sec_edward: sign::SecretKey,
    pub sec_curve: ecdh::Scalar,
}

impl IdentitySecretKey {
    pub fn sign(&self, m: &[u8]) -> Signature {
        Signature {
            sig: sign::sign_detached(m, &self.sec_edward),
        }
    }

    pub fn shared_secret(&self, p: &DHPublicKey) -> Result<[u8; 32], Zero> {
        ecdh::scalarmult(&self.sec_curve, &p.pub_curve)
            .map(|ge| ge.0)
            .map_err(|()| Zero {})
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0).and(e.bytes(&self.sec_edward.0))?;
        e.u8(1).and(e.bytes(&self.sec_curve.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentitySecretKey> {
        let n = d.object()?;
        let mut sec_edward_option = None;
        let mut sec_curve_option = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "IdentitySecretKey::sec_edward",
                    sec_edward_option,
                    Bytes64::decode(d).map(|v| sign::SecretKey(v.array))?
                ),
                1 => uniq!(
                    "IdentitySecretKey::sec_curve",
                    sec_curve_option,
                    Bytes32::decode(d).map(|v| ecdh::Scalar(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        let sec_edward =
            sec_edward_option.ok_or(DecodeError::MissingField("IdentitySecretKey::sec_edward"))?;
        let sec_curve = sec_curve_option.unwrap_or(
            from_ed25519_sk(&sec_edward)
                .map(ecdh::Scalar)
                .map_err(|()| DecodeError::InvalidField("IdentitySecretKey::sec_curve"))?,
        );
        Ok(IdentitySecretKey {
            sec_edward,
            sec_curve,
        })
    }
}

// DHSecretKey ////////////////////////////////////////////////////////////////

#[derive(PartialEq, Debug, Clone)]
pub struct DHSecretKey {
    pub sec_curve: ecdh::Scalar,
}

impl DHSecretKey {
    pub fn shared_secret(&self, p: &DHPublicKey) -> Result<[u8; 32], Zero> {
        ecdh::scalarmult(&self.sec_curve, &p.pub_curve)
            .map(|ge| ge.0)
            .map_err(|()| Zero {})
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(1).and(e.bytes(&self.sec_curve.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<DHSecretKey> {
        let n = d.object()?;
        let mut sec_edward_option = None;
        let mut sec_curve_option = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "DHSecretKey::sec_edward",
                    sec_edward_option,
                    Bytes64::decode(d).map(|v| sign::SecretKey(v.array))?
                ),
                1 => uniq!(
                    "DHSecretKey::sec_curve",
                    sec_curve_option,
                    Bytes32::decode(d).map(|v| ecdh::Scalar(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        if let Some(sec_curve) = sec_curve_option {
            Ok(DHSecretKey { sec_curve })
        } else if let Some(pub_edward) = sec_edward_option {
            let sec_curve = from_ed25519_sk(&pub_edward)
                .map(ecdh::Scalar)
                .map_err(|()| DecodeError::InvalidField("DHSecretKey::sec_curve"))?;
            Ok(DHSecretKey { sec_curve })
        } else {
            Err(DecodeError::MissingField("DHSecretKey::sec_edward"))
        }
    }
}

// IdentityPublicKey ////////////////////////////////////////////////////////////////

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct IdentityPublicKey {
    pub pub_edward: sign::PublicKey,
    pub pub_curve: ecdh::GroupElement,
}

impl IdentityPublicKey {
    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        sign::verify_detached(&s.sig, m, &self.pub_edward)
    }

    pub fn fingerprint(&self) -> String {
        fmt_hex(&self.pub_edward.0)
    }

    pub fn to_dh_public_key(&self) -> DHPublicKey {
        DHPublicKey {
            pub_curve: self.pub_curve.clone(),
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0).and(e.bytes(&self.pub_edward.0))?;
        e.u8(1).and(e.bytes(&self.pub_curve.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityPublicKey> {
        let n = d.object()?;
        let mut pub_edward_option = None;
        let mut pub_curve_option = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "IdentityPublicKey::pub_edward",
                    pub_edward_option,
                    Bytes32::decode(d).map(|v| sign::PublicKey(v.array))?
                ),
                1 => uniq!(
                    "IdentityPublicKey::pub_curve",
                    pub_curve_option,
                    Bytes32::decode(d).map(|v| ecdh::GroupElement(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        let pub_edward =
            pub_edward_option.ok_or(DecodeError::MissingField("IdentityPublicKey::pub_edward"))?;
        let pub_curve = pub_curve_option.unwrap_or(
            from_ed25519_pk(&pub_edward)
                .map(ecdh::GroupElement)
                .map_err(|()| DecodeError::InvalidField("IdentityPublicKey::pub_curve"))?,
        );
        Ok(IdentityPublicKey {
            pub_edward,
            pub_curve,
        })
    }
}

// DHPublicKey ////////////////////////////////////////////////////////////////

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct DHPublicKey {
    pub pub_curve: ecdh::GroupElement,
}

impl DHPublicKey {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(1).and(e.bytes(&self.pub_curve.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<DHPublicKey> {
        let n = d.object()?;
        let mut pub_edward_option = None;
        let mut pub_curve_option = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "DHPublicKey::pub_edward",
                    pub_edward_option,
                    Bytes32::decode(d).map(|v| sign::PublicKey(v.array))?
                ),
                1 => uniq!(
                    "DHPublicKey::pub_curve",
                    pub_curve_option,
                    Bytes32::decode(d).map(|v| ecdh::GroupElement(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        if let Some(pub_curve) = pub_curve_option {
            Ok(DHPublicKey { pub_curve })
        } else if let Some(pub_edward) = pub_edward_option {
            let pub_curve = from_ed25519_pk(&pub_edward)
                .map(ecdh::GroupElement)
                .map_err(|()| DecodeError::InvalidField("DHPublicKey::pub_curve"))?;
            Ok(DHPublicKey { pub_curve })
        } else {
            Err(DecodeError::MissingField("DHPublicKey::pub_edward"))
        }
    }
}

// Random ///////////////////////////////////////////////////////////////////

pub fn rand_bytes(size: usize) -> Vec<u8> {
    randombytes::randombytes(size)
}

// Signature ////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    sig: sign::Signature,
}

impl Signature {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.sig.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Signature> {
        let n = d.object()?;
        let mut sig = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "Signature::sig",
                    sig,
                    Bytes64::decode(d).map(|v| sign::Signature(v.array))?
                ),
                _ => d.skip()?,
            }
        }
        Ok(Signature {
            sig: to_field!(sig, "Signature::sig"),
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
    use super::*;
    use internal::util::roundtrip;

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
        let a = DHKeyPair::new();
        let b = DHKeyPair::new();
        let sa = a.secret_key.shared_secret(&b.public_key);
        let sb = b.secret_key.shared_secret(&a.public_key);
        assert_eq!(&sa, &sb)
    }

    #[test]
    fn sign_and_verify() {
        let a = IdentityKeyPair::new();
        let s = a.secret_key.sign(b"foobarbaz");
        assert!(a.public_key.verify(&s, b"foobarbaz"));
        assert!(!a.public_key.verify(&s, b"foobar"));
    }

    #[test]
    fn enc_dec_pubkey() {
        let k = DHKeyPair::new();
        let r = roundtrip(
            |mut e| k.public_key.encode(&mut e),
            |mut d| DHPublicKey::decode(&mut d),
        );
        assert_eq!(k.public_key, r)
    }

    #[test]
    fn identity() {
        let k = IdentityKeyPair::new();
        let r = roundtrip(
            |mut e| k.secret_key.encode(&mut e),
            |mut d| IdentitySecretKey::decode(&mut d),
        );
        assert_eq!(&k.secret_key.sec_edward.0[..], &r.sec_edward.0[..]);
        assert_eq!(&k.secret_key.sec_curve.0[..], &r.sec_curve.0[..])
    }
    #[test]
    fn enc_dec_dhkey() {
        let k = DHKeyPair::new();
        let r = roundtrip(
            |mut e| k.secret_key.encode(&mut e),
            |mut d| DHSecretKey::decode(&mut d),
        );
        assert_eq!(&k.secret_key.sec_curve.0[..], &r.sec_curve.0[..])
    }
    #[test]
    fn enc_dec_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::new(i.public_key, &k);
        let r = roundtrip(
            |mut e| b.encode(&mut e),
            |mut d| PreKeyBundle::decode(&mut d),
        );
        assert_eq!(None, b.signature);
        assert_eq!(b, r);
    }

    #[test]
    fn enc_dec_signed_prekey_bundle() {
        let i = IdentityKeyPair::new();
        let k = PreKey::new(PreKeyId::new(1));
        let b = PreKeyBundle::signed(&i, &k);
        let r = roundtrip(
            |mut e| b.encode(&mut e),
            |mut d| PreKeyBundle::decode(&mut d),
        );
        assert_eq!(b, r);
        assert_eq!(PreKeyAuth::Valid, b.verify());
        assert_eq!(PreKeyAuth::Valid, r.verify());
    }

    #[test]
    fn degenerated_key() {
        let mut k = DHKeyPair::new();
        for i in 0..k.public_key.pub_curve.0.len() {
            k.public_key.pub_curve.0[i] = 0
        }
        assert_eq!(Err(Zero {}), k.secret_key.shared_secret(&k.public_key))
    }
}
