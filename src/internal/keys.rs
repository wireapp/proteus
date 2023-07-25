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

use crate::error::{ProteusError, ProteusResult};
use crate::internal::types::{DecodeError, DecodeResult, EncodeResult};
use crate::internal::util::{fmt_hex, opt, Bytes32, Bytes64};
use cbor::skip::Skip;
use cbor::{Config, Decoder, Encoder};
use std::fmt::{self, Debug, Formatter};
use std::io::{Cursor, Read, Write};
use std::u16;
use std::vec::Vec;
use zeroize::ZeroizeOnDrop;

// Identity Key /////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IdentityKey {
    pub public_key: PublicKey,
}

impl IdentityKey {
    #[must_use]
    pub fn new(k: PublicKey) -> IdentityKey {
        IdentityKey { public_key: k }
    }

    #[must_use]
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

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "hazmat", derive(PartialEq, Eq))]
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
    #[must_use]
    pub fn new() -> IdentityKeyPair {
        Self::from_keypair(KeyPair::new(None))
    }

    fn from_keypair(k: KeyPair) -> Self {
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
    #[must_use]
    pub unsafe fn from_raw_key_pair(sk: [u8; 64], pk: [u8; 32]) -> ProteusResult<Self> {
        Ok(Self::from_keypair(KeyPair::from_raw(sk, pk)?))
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreKey {
    pub version: u8,
    pub key_id: PreKeyId,
    pub key_pair: KeyPair,
}

impl PreKey {
    #[must_use]
    pub fn new(i: PreKeyId) -> PreKey {
        PreKey {
            version: 1,
            key_id: i,
            key_pair: KeyPair::new(None),
        }
    }

    #[must_use]
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

#[must_use]
pub fn gen_prekeys(start: PreKeyId, size: u16) -> Vec<PreKey> {
    (1..)
        .map(|i| ((u32::from(start.value()) + i) % u32::from(MAX_PREKEY_ID.value())))
        .map(|i| PreKey::new(PreKeyId::new(i as u16)))
        .take(size as usize)
        .collect()
}

// Prekey bundle ////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PreKeyAuth {
    Invalid,
    Valid,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreKeyBundle {
    pub version: u8,
    pub prekey_id: PreKeyId,
    pub public_key: PublicKey,
    pub identity_key: IdentityKey,
    pub signature: Option<Signature>,
}

impl PreKeyBundle {
    #[must_use]
    pub fn new(ident: IdentityKey, key: &PreKey) -> PreKeyBundle {
        PreKeyBundle {
            version: 1,
            prekey_id: key.key_id,
            public_key: key.key_pair.public_key.clone(),
            identity_key: ident,
            signature: None,
        }
    }

    #[must_use]
    pub fn signed(ident: &IdentityKeyPair, key: &PreKey) -> PreKeyBundle {
        let ratchet_key = key.key_pair.public_key.clone();
        let signature = ident.secret_key.sign(ratchet_key.as_slice());
        PreKeyBundle {
            version: 1,
            prekey_id: key.key_id,
            public_key: ratchet_key,
            identity_key: ident.public_key.clone(),
            signature: Some(signature),
        }
    }

    #[must_use]
    pub fn verify(&self) -> PreKeyAuth {
        match self.signature {
            Some(ref sig) => {
                if self
                    .identity_key
                    .public_key
                    .verify(sig, self.public_key.as_slice())
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreKeyId(u16);

pub const MAX_PREKEY_ID: PreKeyId = PreKeyId(u16::MAX);

impl PreKeyId {
    #[must_use]
    pub fn new(i: u16) -> PreKeyId {
        PreKeyId(i)
    }

    #[must_use]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    #[must_use]
    pub fn new(mut seed: Option<zeroize::Zeroizing<[u8; 32]>>) -> KeyPair {
        use rand::{RngCore as _, SeedableRng as _};

        let mut rng = if let Some(seed) = seed.take() {
            rand_chacha::ChaCha20Rng::from_seed(*seed)
        } else {
            rand_chacha::ChaCha20Rng::from_entropy()
        };

        let mut seed = zeroize::Zeroizing::new(ed25519_dalek::SecretKey::default());
        rng.fill_bytes(&mut *seed);

        let kp = ed25519_dalek::SigningKey::from_bytes(&seed);

        let public_key = PublicKey(kp.verifying_key());
        let secret_key = SecretKey(kp);

        KeyPair {
            secret_key,
            public_key,
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
    #[must_use]
    pub unsafe fn from_raw(sk: [u8; 64], pk: [u8; 32]) -> ProteusResult<Self> {
        let sk = ed25519_dalek::SigningKey::from_keypair_bytes(&sk)?;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk)?;
        let secret_key = SecretKey(sk);
        let public_key = PublicKey(pk);

        if secret_key.0.verifying_key() != public_key.0 {
            return Err(ProteusError::PublicKeyMismatch);
        }

        Ok(KeyPair {
            secret_key,
            public_key,
        })
    }
}

// SecretKey ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Zero {}

#[derive(Clone, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SecretKey(ed25519_dalek::SigningKey);

#[cfg(feature = "hazmat")]
impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0
            .to_bytes()
            .as_slice()
            .ct_eq(other.0.to_bytes().as_slice())
            .into()
    }
}

#[cfg(feature = "hazmat")]
impl Eq for SecretKey {}

impl From<ed25519_dalek::SecretKey> for SecretKey {
    fn from(sk: ed25519_dalek::SecretKey) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&sk))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("secret_key", &["[REDACTED]"])
            .finish()
    }
}

impl SecretKey {
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    #[must_use]
    pub fn sign(&self, m: &[u8]) -> Signature {
        use ed25519_dalek::Signer as _;
        Signature(self.0.sign(m))
    }

    #[cfg(feature = "hazmat")]
    pub fn to_bytes(&self) -> [u8; ed25519_dalek::SECRET_KEY_LENGTH] {
        self.0.to_bytes()
    }

    #[cfg(feature = "hazmat")]
    pub fn to_keypair_bytes(&self) -> [u8; ed25519_dalek::KEYPAIR_LENGTH] {
        self.0.to_keypair_bytes()
    }

    pub(crate) fn to_dh(&self) -> x25519_dalek::StaticSecret {
        let seed = self.0.to_bytes();
        let sk_hash = {
            use sha2::Digest as _;
            let mut hash = sha2::Sha512::default();
            hash.update(seed);
            let mut hash_output = hash.finalize();
            hash_output[0] &= 248;
            hash_output[31] &= 63;
            hash_output[31] |= 64;
            hash_output
        };

        let mut dh_sk_raw = zeroize::Zeroizing::new([0u8; 32]);
        dh_sk_raw.copy_from_slice(&sk_hash[..32]);

        x25519_dalek::StaticSecret::from(*dh_sk_raw)
    }

    pub fn shared_secret(
        &self,
        bob_public: &PublicKey,
    ) -> ProteusResult<zeroize::Zeroizing<[u8; 32]>> {
        use subtle::ConstantTimeEq as _;
        if bob_public.0.to_bytes().ct_eq(&[0; 32]).unwrap_u8() == 1 {
            return Err(ProteusError::Zero);
        }

        let alice_x25519_sk = self.to_dh();
        let bob_x25519_pk = bob_public.to_dh()?;

        let shared = alice_x25519_sk.diffie_hellman(&bob_x25519_pk);

        Ok(shared.to_bytes().into())
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0.to_keypair_bytes()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<SecretKey> {
        let n = d.object()?;
        let mut secret_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if secret_key.is_none() => {
                    secret_key = Some(ed25519_dalek::SigningKey::from_keypair_bytes(
                        &Bytes64::decode(d)?.array,
                    )?);
                }
                _ => d.skip()?,
            }
        }
        let secret_key = secret_key.ok_or(DecodeError::MissingField("SecretKey::secret_key"))?;

        Ok(SecretKey(secret_key))
    }
}

// PublicKey ////////////////////////////////////////////////////////////////

// SAFETY: ZeroizeOnDrop isn't needed as ed25519_dalek types already implement Zeroize + Drop
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.to_bytes().ct_eq(&other.0.to_bytes()).into()
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    #[must_use]
    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        use ed25519_dalek::Verifier as _;
        let res = self.0.verify(m, &s.0);

        if let Err(e) = &res {
            println!("{e}");
        }

        res.is_ok()
    }

    #[cfg(feature = "public-key-batch-verification")]
    #[must_use]
    pub fn verify_batch(
        &self,
        verifying_contents: &std::collections::HashMap<Signature, Vec<u8>>,
    ) -> bool {
        let messages: Vec<&[u8]> = verifying_contents.values().map(|m| m.as_slice()).collect();
        let signatures: Vec<_> = verifying_contents.keys().map(|s| s.0).collect();
        let verifying_keys: Vec<_> = (0..signatures.len()).map(|_| self.0.clone()).collect();

        ed25519_dalek::verify_batch(&messages, &signatures, &verifying_keys).is_ok()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub(crate) fn to_dh(&self) -> ProteusResult<x25519_dalek::PublicKey> {
        let pk_montgomery = {
            let edwards = curve25519_dalek::edwards::CompressedEdwardsY(self.0.to_bytes());

            let edwards_relaxed = edwards
                .decompress()
                .ok_or_else(|| ProteusError::Ed25519Error(ed25519_dalek::SignatureError::new()))?;

            zeroize::Zeroizing::new(edwards_relaxed.to_montgomery().to_bytes())
        };

        Ok(x25519_dalek::PublicKey::from(*pk_montgomery))
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        fmt_hex(self.as_slice())
    }

    #[cfg(any(test, feature = "hazmat"))]
    pub fn from_bytes<B: AsRef<[u8]>>(buf: B) -> ProteusResult<Self> {
        let mut pk_raw = zeroize::Zeroizing::new([0u8; ed25519_dalek::PUBLIC_KEY_LENGTH]);
        pk_raw.copy_from_slice(&buf.as_ref()[..ed25519_dalek::PUBLIC_KEY_LENGTH]);

        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_raw)?;

        Ok(PublicKey(pk))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(self.as_slice()))?;
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
        Ok(Self(ed25519_dalek::VerifyingKey::from_bytes(&*pub_edward)?))
    }
}

// Random ///////////////////////////////////////////////////////////////////

#[must_use]
pub fn rand_bytes(size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    use rand::{RngCore as _, SeedableRng as _};
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();
    rng.fill_bytes(&mut buf);
    buf
}

// Signature ////////////////////////////////////////////////////////////////

// SAFETY: ZeroizeOnDrop isn't needed as ed25519_dalek types already implement Zeroize + Drop
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Signature(ed25519_dalek::Signature);

impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.to_bytes());
    }
}

impl Signature {
    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0.to_bytes()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Signature> {
        let n = d.object()?;
        let mut sig = None;
        for _ in 0..n {
            match d.u8()? {
                0 if sig.is_none() => {
                    sig = Some(ed25519_dalek::Signature::from_bytes(
                        &Bytes64::decode(d)?.array,
                    ));
                }
                _ => d.skip()?,
            }
        }
        Ok(Signature(
            sig.ok_or(DecodeError::MissingField("Signature::sig"))?,
        ))
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::util::roundtrip;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn prekey_generation() {
        let k = gen_prekeys(PreKeyId::new(0xFFFC), 5)
            .iter()
            .map(|k| k.key_id.value())
            .collect::<Vec<_>>();
        assert_eq!(vec![0xFFFD, 0xFFFE, 0, 1, 2], k)
    }

    #[test]
    #[wasm_bindgen_test]
    fn dh_agreement() {
        let a = KeyPair::new(None);
        let b = KeyPair::new(None);
        let sa = a.secret_key.shared_secret(&b.public_key).unwrap();
        let sb = b.secret_key.shared_secret(&a.public_key).unwrap();
        assert_eq!(sa, sb)
    }

    #[test]
    #[wasm_bindgen_test]
    fn sign_and_verify() {
        let a = KeyPair::new(None);
        let s = a.secret_key.sign(b"foobarbaz");
        assert!(a.public_key.verify(&s, b"foobarbaz"));
        assert!(!a.public_key.verify(&s, b"foobar"));
    }

    #[test]
    #[wasm_bindgen_test]
    fn enc_dec_pubkey() {
        let k = KeyPair::new(None);
        let r = roundtrip(
            |mut e| k.public_key.encode(&mut e),
            |mut d| PublicKey::decode(&mut d),
        );
        assert_eq!(k.public_key, r)
    }

    #[test]
    #[wasm_bindgen_test]
    fn enc_dec_seckey() {
        let k = KeyPair::new(None);
        let r = roundtrip(
            |mut e| k.secret_key.encode(&mut e),
            |mut d| SecretKey::decode(&mut d),
        );
        assert_eq!(&k.secret_key.0.to_bytes()[..], &r.0.to_bytes()[..]);
        assert_eq!(k.secret_key, r);
    }

    #[test]
    #[wasm_bindgen_test]
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
    #[wasm_bindgen_test]
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
    #[wasm_bindgen_test]
    fn degenerated_key() {
        let k = KeyPair::new(None);
        let bytes: Vec<u8> = k.public_key.as_slice().iter().map(|_| 0).collect();
        let pk = PublicKey::from_bytes(bytes).unwrap();
        let Err(ProteusError::Zero) = k.secret_key.shared_secret(&pk) else {
            panic!("Not a zero pk");
        };
    }
}
