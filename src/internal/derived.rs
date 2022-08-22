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

use hmac::Mac as _;
use std::io::Write;
use std::ops::Deref;
use std::vec::Vec;

use super::types::InternalError;

type HmacSha256 = hmac::SimpleHmac<sha2::Sha256>;
type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;

// Derived Secrets //////////////////////////////////////////////////////////
#[derive(Clone)]
pub struct DerivedSecrets {
    pub cipher_key: CipherKey,
    pub mac_key: MacKey,
}

impl DerivedSecrets {
    pub fn kdf(
        input: &[u8],
        salt: Option<&[u8]>,
        info: &[u8],
    ) -> Result<DerivedSecrets, InternalError> {
        let mut ck = [0u8; 32];
        let mut mk = [0u8; 32];

        let hkdf = HkdfSha256::new(salt, input);
        let mut okm = zeroize::Zeroizing::new([0u8; 64]);
        hkdf.expand(info, okm.as_mut())?;

        ck.as_mut().write_all(&okm[0..32])?;
        mk.as_mut().write_all(&okm[32..64])?;

        Ok(DerivedSecrets {
            cipher_key: CipherKey::new(ck),
            mac_key: MacKey::new(mk),
        })
    }

    pub fn kdf_without_salt(input: &[u8], info: &[u8]) -> Result<DerivedSecrets, InternalError> {
        Self::kdf(input, None, info)
    }
}

// Cipher Key ///////////////////////////////////////////////////////////////
#[derive(minicbor::Encode, minicbor::Decode, Clone, Debug)]
pub struct CipherKey {
    #[cbor(n(0), with = "minicbor::bytes")]
    key: chacha20::Key,
}

impl CipherKey {
    pub fn new(b: [u8; 32]) -> CipherKey {
        CipherKey {
            key: chacha20::Key::clone_from_slice(&b),
        }
    }

    pub fn encrypt(&self, text: &[u8], nonce: &[u8]) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
        let nonce = chacha20::LegacyNonce::from_slice(nonce);
        let mut cipher = chacha20::ChaCha20Legacy::new(&self.key, nonce);
        let mut data = Vec::from(text);
        cipher.apply_keystream(&mut data);
        data
    }

    pub fn decrypt(&self, data: &[u8], nonce: &[u8]) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit as _, StreamCipher as _, StreamCipherSeek as _};
        let nonce = chacha20::LegacyNonce::from_slice(nonce);
        let mut cipher = chacha20::ChaCha20Legacy::new(&self.key, nonce);
        let mut text = Vec::from(data);
        cipher.seek(0);
        cipher.apply_keystream(&mut text);
        text
    }
}

impl Deref for CipherKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.key.as_slice()
    }
}

// MAC Key //////////////////////////////////////////////////////////////////
#[derive(minicbor::Encode, minicbor::Decode, Clone, Debug)]
pub struct MacKey {
    #[cbor(n(0), with = "minicbor::bytes")]
    key: zeroize::Zeroizing<[u8; 32]>,
}

impl MacKey {
    pub fn new(b: [u8; 32]) -> MacKey {
        MacKey {
            key: zeroize::Zeroizing::new(b),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Mac {
        // SAFETY: self.key is 32 bytes so this call always succeeds
        let mut mac = HmacSha256::new_from_slice(&*self.key).unwrap();
        mac.update(msg);

        Mac::new(mac.finalize())
    }

    pub fn verify(&self, sig: &Mac, msg: &[u8]) -> bool {
        // SAFETY: self.key is 32 bytes so this call always succeeds
        let mut mac = HmacSha256::new_from_slice(&*self.key).unwrap();
        mac.update(msg);
        mac.verify_slice(sig).map(|_| true).unwrap_or(false)
    }
}

impl Drop for MacKey {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.key.zeroize();
    }
}

// MAC //////////////////////////////////////////////////////////////////////
#[derive(Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
pub struct Mac {
    #[cbor(n(0), with = "minicbor::bytes")]
    sig_bytes: [u8; 32],
}

impl Mac {
    pub fn new(signature: hmac::digest::CtOutput<HmacSha256>) -> Self {
        let mut sig_bytes = [0u8; 32];
        sig_bytes.copy_from_slice(&signature.clone().into_bytes().as_slice()[..32]);

        Self { sig_bytes }
    }

    pub fn into_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.sig_bytes);
        bytes
    }
}

impl Deref for Mac {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.sig_bytes
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[test]
#[wasm_bindgen_test::wasm_bindgen_test]
fn derive_secrets() {
    let nc = chacha20::LegacyNonce::from_slice(&[0; 8]);
    let ds = DerivedSecrets::kdf_without_salt(b"346234876", b"foobar").unwrap();
    let ct = ds.cipher_key.encrypt(b"plaintext", &nc);
    assert_eq!(ct.len(), b"plaintext".len());
    assert!(ct != b"plaintext");
    assert_eq!(ds.cipher_key.decrypt(&ct, &nc), b"plaintext");
}
