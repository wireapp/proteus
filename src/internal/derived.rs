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

use crate::internal::{
    types::{DecodeError, DecodeResult, EncodeResult, InternalError},
    util::Bytes32,
};
use cbor::{skip::Skip, Decoder, Encoder};
use hmac::Mac as _;
use std::{
    io::{Read, Write},
    ops::Deref,
    vec::Vec,
};
use zeroize::ZeroizeOnDrop;

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

#[derive(Clone, Debug, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct CipherKey(chacha20::Key);

impl CipherKey {
    #[must_use]
    pub fn new(b: [u8; 32]) -> CipherKey {
        CipherKey(chacha20::Key::clone_from_slice(&b))
    }

    #[must_use]
    pub fn encrypt(&self, text: &[u8], nonce: chacha20::LegacyNonce) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
        // let nonce = chacha20::LegacyNonce::from_slice(nonce);
        let mut cipher = chacha20::ChaCha20Legacy::new(&self.0, &nonce);
        let mut data = Vec::from(text);
        cipher.apply_keystream(&mut data);
        data
    }

    #[must_use]
    pub fn decrypt(&self, data: &[u8], nonce: chacha20::LegacyNonce) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit as _, StreamCipher as _, StreamCipherSeek as _};
        let nonce = chacha20::LegacyNonce::from_slice(&nonce);
        let mut cipher = chacha20::ChaCha20Legacy::new(&self.0, nonce);
        let mut text = Vec::from(data);
        cipher.seek(0);
        cipher.apply_keystream(&mut text);
        text
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(self.0.as_slice()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<CipherKey> {
        let n = d.object()?;
        let mut key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if key.is_none() => {
                    key = Some(
                        Bytes32::decode(d).map(|v| chacha20::Key::clone_from_slice(&*v.array))?,
                    )
                }
                _ => d.skip()?,
            }
        }
        Ok(CipherKey(
            key.ok_or(DecodeError::MissingField("CipherKey::key"))?,
        ))
    }
}

impl Deref for CipherKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

// MAC Key //////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct MacKey([u8; 32]);

impl MacKey {
    #[must_use]
    pub fn new(b: [u8; 32]) -> MacKey {
        MacKey(b)
    }

    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Mac {
        let mut mac = HmacSha256::new_from_slice(&self.0).unwrap();
        mac.update(msg);

        Mac::new(mac.finalize())
    }

    #[must_use]
    pub fn verify(&self, sig: &Mac, msg: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.0).unwrap();
        mac.update(msg);
        mac.verify_slice(sig).map(|_| true).unwrap_or(false)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<MacKey> {
        let n = d.object()?;
        let mut key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if key.is_none() => key = Some(Bytes32::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(MacKey(
            *key.map(|bytes| bytes.array)
                .ok_or(DecodeError::MissingField("MacKey::key"))?,
        ))
    }
}

// MAC //////////////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
#[repr(transparent)]
pub struct Mac([u8; 32]);

impl Mac {
    #[must_use]
    pub fn new(signature: hmac::digest::CtOutput<HmacSha256>) -> Self {
        Self(signature.into_bytes().into())
    }

    #[must_use]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.0))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Self> {
        let n = d.object()?;
        let mut sig = None;
        for _ in 0..n {
            match d.u8()? {
                0 if sig.is_none() => sig = Some(Bytes32::decode(d).map(|v| v.array)?),
                _ => d.skip()?,
            }
        }

        let sig = sig.ok_or(DecodeError::MissingField("Mac::sig"))?;

        Ok(Self(*sig))
    }
}

impl Deref for Mac {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn derive_secrets() {
        let nc = chacha20::LegacyNonce::from([0u8; 8]);
        let ds = DerivedSecrets::kdf_without_salt(b"346234876", b"foobar").unwrap();
        let ct = ds.cipher_key.encrypt(b"plaintext", nc);
        assert_eq!(ct.len(), b"plaintext".len());
        assert!(ct != b"plaintext");
        assert_eq!(ds.cipher_key.decrypt(&ct, nc), b"plaintext");
    }
}
