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
use cbor::{Decoder, Encoder};
use crate::internal::types::{DecodeError, DecodeResult, EncodeResult};
use crate::internal::util::Bytes32;
use hmac::Mac as _;
use std::io::{Read, Write};
use std::ops::Deref;
use std::vec::Vec;

type HmacSha256 = hmac::SimpleHmac<sha2::Sha256>;
type HkdfSha256 = hkdf::Hkdf<sha2::Sha256>;

// Derived Secrets //////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct DerivedSecrets {
    pub cipher_key: CipherKey,
    pub mac_key: MacKey,
}

impl DerivedSecrets {
    pub fn kdf(input: &[u8], salt: Option<&[u8]>, info: &[u8]) -> DerivedSecrets {
        let mut ck = [0u8; 32];
        let mut mk = [0u8; 32];

        let hkdf = HkdfSha256::new(salt, input);
        let mut okm = zeroize::Zeroizing::new([0u8; 64]);
        // FIXME: Expand phase is faillible, we should break API and return a Result
        hkdf.expand(info, okm.as_mut()).unwrap();

        ck.as_mut().write_all(&okm[0..32]).unwrap();
        mk.as_mut().write_all(&okm[32..64]).unwrap();

        DerivedSecrets {
            cipher_key: CipherKey::new(ck),
            mac_key: MacKey::new(mk),
        }
    }

    pub fn kdf_without_salt(input: &[u8], info: &[u8]) -> DerivedSecrets {
        Self::kdf(input, None, info)
    }
}

// Cipher Key ///////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct CipherKey {
    key: chacha20::Key,
}

impl CipherKey {
    pub fn new(b: [u8; 32]) -> CipherKey {
        CipherKey {
            key: chacha20::Key::clone_from_slice(&b),
        }
    }

    pub fn encrypt(&self, text: &[u8], nonce: &[u8]) -> Vec<u8> {
        use chacha20::cipher::{StreamCipher as _, NewCipher as _};
        let nonce = chacha20::Nonce::from_slice(nonce);
        let mut cipher = chacha20::ChaCha20::new(&self.key, nonce);
        let mut data = Vec::from(text);
        cipher.apply_keystream(&mut data);
        data
    }

    pub fn decrypt(&self, data: &[u8], nonce: &[u8]) -> Vec<u8> {
        use chacha20::cipher::{
            StreamCipher as _,
            StreamCipherSeek as _,
            NewCipher as _
        };
        let nonce = chacha20::Nonce::from_slice(nonce);
        let mut cipher = chacha20::ChaCha20::new(&self.key, nonce);
        let mut text = Vec::from(data);
        cipher.seek(0);
        cipher.apply_keystream(&mut text);
        text
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(self.key.as_slice()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<CipherKey> {
        let n = d.object()?;
        let mut key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if key.is_none() => key = Some(
                    Bytes32::decode(d).map(|v|
                        chacha20::Key::clone_from_slice(&*v.array)
                    )?
                ),
                _ => d.skip()?,
            }
        }
        Ok(CipherKey {
            key: key.ok_or_else(|| DecodeError::MissingField("CipherKey::key"))?,
        })
    }
}

impl Deref for CipherKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.key.as_slice()
    }
}

// MAC Key //////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
pub struct MacKey {
    key: zeroize::Zeroizing<[u8; 32]>,
}

impl MacKey {
    pub fn new(b: [u8; 32]) -> MacKey {
        MacKey { key: zeroize::Zeroizing::new(b) }
    }

    pub fn sign(&self, msg: &[u8]) -> Mac {
        let mut mac = HmacSha256::new_from_slice(&*self.key).unwrap();
        mac.update(msg);

        Mac {
            sig: mac.finalize(),
        }
    }

    pub fn verify(&self, sig: &Mac, msg: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&*self.key).unwrap();
        mac.update(msg);
        mac.verify_slice(sig).map(|_| true).unwrap_or(false)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&*self.key))?;
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
        Ok(MacKey {
            key: key
                .map(|bytes| bytes.array)
                .ok_or_else(|| DecodeError::MissingField("MacKey::key"))?,
        })
    }
}

impl Drop for MacKey {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.key.zeroize();
    }
}

// MAC //////////////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq)]
pub struct Mac {
    sig: hmac::digest::CtOutput<HmacSha256>,
}

impl Mac {
    pub fn into_bytes(self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.sig.into_bytes().as_slice()[..32]);
        bytes
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0).and(e.bytes(&self.sig.into_bytes()))?;
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Mac> {
        let n = d.object()?;
        let mut sig = None;
        for _ in 0..n {
            match d.u8()? {
                0 if sig.is_none() => sig = Some(
                    Bytes32::decode(d)
                        .map(|v| hmac::digest::CtOutput::new(
                            (*v.array).into()
                        ))?
                ),
                _ => d.skip()?,
            }
        }
        Ok(Mac {
            sig: sig.ok_or_else(|| DecodeError::MissingField("Mac::sig"))?,
        })
    }
}

impl Deref for Mac {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.sig.into_bytes()
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[test]
fn derive_secrets() {
    let nc = chacha20::Nonce::from_slice(&[0; 8]);
    let ds = DerivedSecrets::kdf_without_salt(b"346234876", b"foobar");
    let ct = ds.cipher_key.encrypt(b"plaintext", &nc);
    assert_eq!(ct.len(), b"plaintext".len());
    assert!(ct != b"plaintext");
    assert_eq!(ds.cipher_key.decrypt(&ct, &nc), b"plaintext");
}
