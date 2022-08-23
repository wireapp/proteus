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
//use crate::internal::ffi;
use crate::internal::types::{DecodeError, DecodeResult, EncodeResult};
use crate::internal::util::{fmt_hex, opt, Bytes32, Bytes64};
// use sodiumoxide::crypto::scalarmult as ecdh;
// use sodiumoxide::crypto::sign;
use std::fmt::{self, Debug, Error, Formatter};
use std::io::{Cursor, Read, Write};
use std::u16;
use std::vec::Vec;

// Identity Key /////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityKey {
    pub public_key: PublicKey,
}

impl IdentityKey {
    pub fn new(k: PublicKey) -> IdentityKey {
        IdentityKey { public_key: k }
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
                0 if public_key.is_none() => public_key = Some(PublicKey::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(IdentityKey {
            public_key: public_key.ok_or(DecodeError::MissingField("IdentityKey::public_key"))?,
        })
    }
}

// Identity Keypair /////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct IdentityKeyPair {
    pub version: u8,
    pub secret_key: SecretKey,
    pub public_key: IdentityKey,
}

impl Default for IdentityKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityKeyPair {
    pub fn new() -> IdentityKeyPair {
        let k = KeyPair::new();
        IdentityKeyPair {
            version: 1,
            secret_key: k.secret_key,
            public_key: IdentityKey {
                public_key: k.public_key,
            },
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
        e.object(3)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.secret_key.encode(e)?;
        e.u8(2)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<IdentityKeyPair> {
        let n = d.object()?;
        let mut version = None;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if version.is_none() => version = Some(d.u8()?),
                1 if secret_key.is_none() => secret_key = Some(SecretKey::decode(d)?),
                2 if public_key.is_none() => public_key = Some(IdentityKey::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(IdentityKeyPair {
            version: version.ok_or(DecodeError::MissingField("IdentityKeyPair::version"))?,
            secret_key: secret_key
                .ok_or(DecodeError::MissingField("IdentityKeyPair::secret_key"))?,
            public_key: public_key
                .ok_or(DecodeError::MissingField("IdentityKeyPair::public_key"))?,
        })
    }

    #[cfg(feature = "hazmat")]
    pub fn from_raw_secret_key(raw: [u8; 64]) -> Self {
        Self::from_keypair(KeyPair::from_secret_key_raw(raw))
    }

    #[cfg(feature = "hazmat")]
    pub fn from_raw_secret_key_std(raw: [u8; 32]) -> Self {
        Self::from_keypair(KeyPair::from_secret_key_raw_std(raw))
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct PreKey {
    pub version: u8,
    pub key_id: PreKeyId,
    pub key_pair: KeyPair,
}

impl PreKey {
    pub fn new(i: PreKeyId) -> PreKey {
        PreKey {
            version: 1,
            key_id: i,
            key_pair: KeyPair::new(),
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
                0 if version.is_none() => version = Some(d.u8()?),
                1 if key_id.is_none() => key_id = Some(PreKeyId::decode(d)?),
                2 if key_pair.is_none() => key_pair = Some(KeyPair::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(PreKey {
            version: version.ok_or(DecodeError::MissingField("PreKey::version"))?,
            key_id: key_id.ok_or(DecodeError::MissingField("PreKey::key_id"))?,
            key_pair: key_pair.ok_or(DecodeError::MissingField("PreKey::key_pair"))?,
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
    pub public_key: PublicKey,
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
        let signature = ident.secret_key.sign(&ratchet_key.0.to_bytes());
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
                    .verify(sig, &self.public_key.0.to_bytes())
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
                0 if version.is_none() => version = Some(d.u8()?),
                1 if prekey_id.is_none() => prekey_id = Some(PreKeyId::decode(d)?),
                2 if public_key.is_none() => public_key = Some(PublicKey::decode(d)?),
                3 if identity_key.is_none() => identity_key = Some(IdentityKey::decode(d)?),
                4 if signature.is_none() => signature = Some(opt(Signature::decode(d))?),
                _ => d.skip()?,
            }
        }
        Ok(PreKeyBundle {
            version: version.ok_or(DecodeError::MissingField("PreKeyBundle::version"))?,
            prekey_id: prekey_id.ok_or(DecodeError::MissingField("PreKeyBundle::prekey_id"))?,
            public_key: public_key.ok_or(DecodeError::MissingField("PreKeyBundle::public_key"))?,
            identity_key: identity_key
                .ok_or(DecodeError::MissingField("PreKeyBundle::identity_key"))?,
            signature: signature.flatten(),
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

// Keypair //////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    pub fn new() -> KeyPair {
        use rand::{RngCore as _, SeedableRng as _};
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

        let mut sk_raw = [0u8; 32];
        rng.fill_bytes(&mut sk_raw);
        let sk_not_weird = ed25519_dalek::SecretKey::from_bytes(&sk_raw).unwrap();
        let sk_weird = ed25519_dalek::ExpandedSecretKey::from(&sk_not_weird);
        let pk = ed25519_dalek::PublicKey::from(&sk_weird);

        KeyPair {
            secret_key: SecretKey(sk_weird),
            public_key: PublicKey(pk),
        }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0)?;
        self.secret_key.encode(e)?;
        e.u8(1)?;
        self.public_key.encode(e)
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<KeyPair> {
        let n = d.object()?;
        let mut secret_key = None;
        let mut public_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if secret_key.is_none() => secret_key = Some(SecretKey::decode(d)?),
                1 if public_key.is_none() => public_key = Some(PublicKey::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(KeyPair {
            secret_key: secret_key.ok_or(DecodeError::MissingField("KeyPair::secret_key"))?,
            public_key: public_key.ok_or(DecodeError::MissingField("KeyPair::public_key"))?,
        })
    }

    #[cfg(feature = "hazmat")]
    pub fn from_secret_key_raw_std(sk_raw: [u8; 32]) -> Self {
        let sk_not_weird = ed25519_dalek::SecretKey::from_bytes(&sk_raw).unwrap();
        let sk_weird = ed25519_dalek::ExpandedSecretKey::from(&sk_not_weird);
        let pk = ed25519_dalek::PublicKey::from(&sk_weird);

        KeyPair {
            secret_key: SecretKey(sk_weird),
            public_key: PublicKey(pk),
        }
    }

    #[cfg(feature = "hazmat")]
    pub fn from_secret_key_raw(sk_raw: [u8; 64]) -> Self {
        let sk_weird = ed25519_dalek::ExpandedSecretKey::from_bytes(&sk_raw).unwrap();
        let pk = ed25519_dalek::PublicKey::from(&sk_weird);

        KeyPair {
            secret_key: SecretKey(sk_weird),
            public_key: PublicKey(pk),
        }
    }
}

// SecretKey ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Zero {}

pub struct SecretKey(ed25519_dalek::ExpandedSecretKey);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("secret_key", &["[REDACTED]"])
            .finish()
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self(ed25519_dalek::ExpandedSecretKey::from_bytes(&self.0.to_bytes()).unwrap())
    }
}

impl SecretKey {
    pub fn sign(&self, m: &[u8]) -> Signature {
        let pk = ed25519_dalek::PublicKey::from(&self.0);
        Signature {
            sig: self.0.sign(m, &pk),
        }
    }

    pub fn shared_secret(&self, bob_public: &PublicKey) -> Result<[u8; 32], Zero> {
        let bob_pk = bob_public.0.to_bytes();
        let zero_slice = [0u8; 32];

        use subtle::ConstantTimeEq as _;
        if bob_pk.ct_eq(&zero_slice).unwrap_u8() == 1 {
            return Err(Zero {});
        }

        let bob_pk_montgomery = curve25519_dalek::edwards::CompressedEdwardsY(bob_pk)
            .decompress()
            .unwrap()
            .to_montgomery();

        let mut alice_sk = zeroize::Zeroizing::new(zero_slice);
        alice_sk.copy_from_slice(&self.0.to_bytes()[..32]);

        let alice_secret = x25519_dalek::StaticSecret::from(*alice_sk);
        let bob_public = x25519_dalek::PublicKey::from(bob_pk_montgomery.to_bytes());
        let shared = alice_secret.diffie_hellman(&bob_public);
        Ok(shared.to_bytes())
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0.to_bytes()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<SecretKey> {
        let n = d.object()?;
        let mut secret_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if secret_key.is_none() => {
                    secret_key = Some(ed25519_dalek::ExpandedSecretKey::from_bytes(
                        &*Bytes64::decode(d)?.array,
                    )?)
                }
                _ => d.skip()?,
            }
        }
        let secret_key = secret_key.ok_or(DecodeError::MissingField("SecretKey::secret_key"))?;

        Ok(SecretKey(secret_key))
    }

    #[cfg(feature = "hazmat")]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut ret = [0; 32];
        ret.copy_from_slice(&self.0.to_bytes()[..32]);
        ret
    }

    #[cfg(feature = "hazmat")]
    pub fn to_bytes_extended(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

// PublicKey ////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct PublicKey(ed25519_dalek::PublicKey);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        let ct = self.0.as_bytes().ct_eq(other.0.as_bytes());

        ct.unwrap_u8() == 1
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        let res = self.0.verify_strict(m, &s.sig);

        if let Err(e) = &res {
            println!("{}", e);
        }

        res.is_ok()
    }

    pub fn fingerprint(&self) -> String {
        fmt_hex(self.0.as_bytes())
    }

    pub(crate) fn from_bytes<B: AsRef<[u8]>>(buf: B) -> DecodeResult<Self> {
        let edward = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&buf.as_ref()[..32]);
        let pk = ed25519_dalek::PublicKey::from_bytes(edward.as_bytes())?;

        Ok(PublicKey(pk))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(self.0.as_bytes()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PublicKey> {
        let n = d.object()?;
        let mut pub_edward = None;
        for _ in 0..n {
            match d.u8()? {
                0 if pub_edward.is_none() => {
                    let bytes = Bytes32::decode(d)?;
                    pub_edward = Some(bytes.array);
                }
                _ => d.skip()?,
            }
        }
        let pub_edward = pub_edward.ok_or(DecodeError::MissingField("PublicKey::pub_edward"))?;
        Self::from_bytes(*pub_edward)
    }
}

// Random ///////////////////////////////////////////////////////////////////

pub fn rand_bytes(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    use rand::{RngCore as _, SeedableRng as _};
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();
    rng.fill_bytes(&mut buf);
    buf
}

// Signature ////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    sig: ed25519_dalek::Signature,
}

impl Signature {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.sig.to_bytes()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Signature> {
        let n = d.object()?;
        let mut sig = None;
        for _ in 0..n {
            match d.u8()? {
                0 if sig.is_none() => {
                    sig = Some(ed25519_dalek::Signature::from_bytes(
                        &*Bytes64::decode(d)?.array,
                    )?)
                }
                _ => d.skip()?,
            }
        }
        Ok(Signature {
            sig: sig.ok_or(DecodeError::MissingField("Signature::sig"))?,
        })
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::util::roundtrip;

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
        let a = KeyPair::new();
        let b = KeyPair::new();
        let sa = a.secret_key.shared_secret(&b.public_key).unwrap();
        let sb = b.secret_key.shared_secret(&a.public_key).unwrap();
        assert_eq!(sa, sb)
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
        let r = roundtrip(
            |mut e| k.public_key.encode(&mut e),
            |mut d| PublicKey::decode(&mut d),
        );
        assert_eq!(k.public_key, r)
    }

    #[test]
    fn enc_dec_seckey() {
        let k = KeyPair::new();
        let r = roundtrip(
            |mut e| k.secret_key.encode(&mut e),
            |mut d| SecretKey::decode(&mut d),
        );
        assert_eq!(&k.secret_key.0.to_bytes()[..], &r.0.to_bytes()[..]);
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
        let k = KeyPair::new();
        let bytes: Vec<u8> = k.public_key.0.to_bytes().into_iter().map(|_| 0).collect();
        let pk = PublicKey::from_bytes(bytes).unwrap();
        assert_eq!(Err(Zero {}), k.secret_key.shared_secret(&pk))
    }
}
