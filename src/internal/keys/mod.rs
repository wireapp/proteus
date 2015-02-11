// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use internal::ffi;
use internal::util;
use sodiumoxide::crypto::scalarmult as ecdh;
use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes;
use std::fmt::{Debug, Formatter, Error};
use std::iter::iterate;
use std::u16;

pub mod binary;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct IdentityKey {
    pub public_key: PublicKey
}

impl IdentityKey {
    pub fn new(k: PublicKey) -> IdentityKey {
        IdentityKey { public_key: k }
    }
}

// Identity Keypair /////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct IdentityKeyPair {
    pub secret_key: SecretKey,
    pub public_key: IdentityKey
}

impl IdentityKeyPair {
    pub fn new() -> IdentityKeyPair {
        let k = KeyPair::new();
        IdentityKeyPair {
            secret_key: k.secret_key,
            public_key: IdentityKey { public_key: k.public_key }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        util::encode(self, binary::enc_identity_keypair).unwrap()
    }

    pub fn decode(b: &[u8]) -> Option<IdentityKeyPair> {
        util::decode(b, binary::dec_identity_keypair).ok()
    }
}

// Prekey ///////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct PreKey {
    pub key_id:   PreKeyId,
    pub key_pair: KeyPair
}

impl PreKey {
    pub fn new(i: PreKeyId) -> PreKey {
        PreKey { key_id: i, key_pair: KeyPair::new() }
    }

    pub fn last_resort() -> PreKey {
        PreKey::new(MAX_PREKEY_ID)
    }

    pub fn encode(&self) -> Vec<u8> {
        util::encode(self, binary::enc_prekey).unwrap()
    }

    pub fn decode(b: &[u8]) -> Option<PreKey> {
        util::decode(b, binary::dec_prekey).ok()
    }
}

pub fn gen_prekeys(start: PreKeyId, size: u16) -> Vec<PreKey> {
    iterate(start.value(), |i| (i + 1) % MAX_PREKEY_ID.value())
        .map(|i| PreKey::new(PreKeyId::new(i)))
        .take(size as usize)
        .collect()
}

// Prekey bundle ////////////////////////////////////////////////////////////

#[derive(Copy, PartialEq, Eq, Debug)]
pub struct PreKeyBundle {
    pub prekey_id:    PreKeyId,
    pub public_key:   PublicKey,
    pub identity_key: IdentityKey
}

impl PreKeyBundle {
    pub fn new(ident: IdentityKey, key: &PreKey) -> PreKeyBundle {
        PreKeyBundle {
            prekey_id:    key.key_id,
            public_key:   key.key_pair.public_key,
            identity_key: ident
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        util::encode(self, binary::enc_prekey_bundle).unwrap()
    }

    pub fn decode(b: &[u8]) -> Option<PreKeyBundle> {
        util::decode(b, binary::dec_prekey_bundle).ok()
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
}

// PublicKey ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone)]
pub struct PublicKey {
    pub_edward: sign::PublicKey,
    pub_curve:  ecdh::GroupElement
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.pub_edward.0.as_slice() == other.pub_edward.0.as_slice()
            &&
        self.pub_curve.0.as_slice() == other.pub_curve.0.as_slice()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:?}", self.pub_edward.0.as_slice())
    }
}

impl PublicKey {
    pub fn verify(&self, s: &Signature, m: &[u8]) -> bool {
        sign::verify_detached(&s.sig, m, &self.pub_edward)
    }
}

// Random ///////////////////////////////////////////////////////////////////

pub fn rand_bytes(size: usize) -> Vec<u8> {
    randombytes::randombytes(size)
}

// Signature ////////////////////////////////////////////////////////////////

#[derive(Copy, Clone)]
pub struct Signature {
    sig: sign::Signature
}

// Internal /////////////////////////////////////////////////////////////////

pub fn from_ed25519_pk(k: &sign::PublicKey) -> [u8; ecdh::BYTES] {
    let mut ep = [0u8; ecdh::BYTES];
    unsafe {
        ffi::crypto_sign_ed25519_pk_to_curve25519(ep.as_mut_ptr(), k.0.as_slice().as_ptr());
    }
    ep
}

pub fn from_ed25519_sk(k: &sign::SecretKey) -> [u8; ecdh::SCALARBYTES] {
    let mut es = [0u8; ecdh::SCALARBYTES];
    unsafe {
        ffi::crypto_sign_ed25519_sk_to_curve25519(es.as_mut_ptr(), k.0.as_slice().as_ptr());
    }
    es
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dh_agreement() {
        let a  = KeyPair::new();
        let b  = KeyPair::new();
        let sa = a.secret_key.shared_secret(&b.public_key);
        let sb = b.secret_key.shared_secret(&a.public_key);
        assert_eq!(sa.as_slice(), sb.as_slice())
    }

    #[test]
    fn sign_and_verify() {
        let a = KeyPair::new();
        let s = a.secret_key.sign(b"foobarbaz");
        assert!(a.public_key.verify(&s, b"foobarbaz"));
        assert!(!a.public_key.verify(&s, b"foobar"));
    }
}
