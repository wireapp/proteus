// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use hkdf::{Info, Input, Len, Salt, hkdf};
use sodiumoxide::crypto::stream;
use sodiumoxide::crypto::auth::hmacsha256 as mac;
use std::ops::Deref;
use std::slice::bytes::copy_memory;
use std::vec::Vec;

pub mod binary;

// Derived Secrets //////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct DerivedSecrets {
    pub cipher_key: CipherKey,
    pub mac_key:    MacKey
}

impl DerivedSecrets {
    pub fn kdf(input: Input, salt: Salt, info: Info) -> DerivedSecrets {
        let mut ck = [0u8; 32];
        let mut mk = [0u8; 32];

        let len = Len::new(64).expect("Unexpected hkdf::HASH_LEN.");
        let okm = hkdf(salt, input, info, len);

        copy_memory(&okm[0  .. 32], &mut ck);
        copy_memory(&okm[32 .. 64], &mut mk);

        DerivedSecrets {
            cipher_key: CipherKey::new(ck),
            mac_key:    MacKey::new(mk)
        }
    }

    pub fn kdf_without_salt(input: Input, info: Info) -> DerivedSecrets {
        DerivedSecrets::kdf(input, Salt(b""), info)
    }
}

// Cipher Key ///////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct CipherKey {
    key: stream::Key
}

impl CipherKey {
    pub fn new(b: [u8; 32]) -> CipherKey {
        CipherKey { key: stream::Key(b) }
    }

    pub fn encrypt(&self, text: &[u8], nonce: &Nonce) -> Vec<u8> {
        stream::stream_xor(text, &nonce.0, &self.key)
    }

    pub fn decrypt(&self, text: &[u8], nonce: &Nonce) -> Vec<u8> {
        stream::stream_xor(text, &nonce.0, &self.key)
    }
}

impl Deref for CipherKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.key.0
    }
}

// Nonce ////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone)]
pub struct Nonce(stream::Nonce);

impl Nonce {
    pub fn new(b: [u8; 24]) -> Nonce {
        Nonce(stream::Nonce(b))
    }
}

// MAC Key //////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct MacKey {
    key: mac::Key
}

impl MacKey {
    pub fn new(b: [u8; 32]) -> MacKey {
        MacKey { key: mac::Key(b) }
    }

    pub fn sign(&self, msg: &[u8]) -> Mac {
        Mac { sig: mac::authenticate(msg, &self.key) }
    }

    pub fn verify(&self, sig: &Mac, msg: &[u8]) -> bool {
        mac::verify(&sig.sig, msg, &self.key)
    }
}

// MAC //////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Mac {
    sig: mac::Tag
}

impl Mac {
    pub fn to_bytes(self) -> [u8; 32] {
        self.sig.0
    }
}

impl Deref for Mac {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.sig.0
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[test]
fn derive_secrets() {
    let nc = Nonce::new([0; 24]);
    let ds = DerivedSecrets::kdf_without_salt(Input(b"346234876"), Info(b"foobar"));
    let ct = ds.cipher_key.encrypt(b"plaintext", &nc);
    assert_eq!(ct.len(), b"plaintext".len());
    assert!(ct != b"plaintext");
    assert_eq!(ds.cipher_key.decrypt(&ct, &nc), b"plaintext");
}
