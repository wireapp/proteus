// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
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

use cbor::{Decoder, Encoder};
use cbor::skip::Skip;
use hkdf::{Info, Input, Len, Salt, hkdf};
use internal::types::{DecodeError, DecodeResult, EncodeResult};
use internal::util::Bytes32;
use sodiumoxide::crypto::stream::chacha20 as stream;
use sodiumoxide::crypto::auth::hmacsha256 as mac;
use std::io::{Read, Write};
use std::ops::Deref;
use std::vec::Vec;

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

        ck.as_mut().write_all(&okm[0  .. 32]).unwrap();
        mk.as_mut().write_all(&okm[32 .. 64]).unwrap();

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

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.key.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<CipherKey> {
        let n = try!(d.object());
        let mut key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => key = Some(try!(Bytes32::decode(d).map(|v| stream::Key(v.array)))),
                _ => try!(d.skip())
            }
        }
        Ok(CipherKey { key: to_field!(key, "CipherKey::key") })
    }
}

impl Deref for CipherKey {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.key.0
    }
}

// Nonce ////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct Nonce(stream::Nonce);

impl Nonce {
    pub fn new(b: [u8; 8]) -> Nonce {
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

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.key.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<MacKey> {
        let n = try!(d.object());
        let mut key = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => key = Some(try!(Bytes32::decode(d).map(|v| mac::Key(v.array)))),
                _ => try!(d.skip())
            }
        }
        Ok(MacKey { key: to_field!(key, "MacKey::key") })
    }
}

// MAC //////////////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq)]
pub struct Mac {
    sig: mac::Tag
}

impl Mac {
    pub fn into_bytes(self) -> [u8; 32] {
        self.sig.0
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(1));
        try!(e.u8(0).and(e.bytes(&self.sig.0)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Mac> {
        let n = try!(d.object());
        let mut sig = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => sig = Some(try!(Bytes32::decode(d).map(|v| mac::Tag(v.array)))),
                _ => try!(d.skip())
            }
        }
        Ok(Mac { sig: to_field!(sig, "Mac::sig") })
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
    let nc = Nonce::new([0; 8]);
    let ds = DerivedSecrets::kdf_without_salt(Input(b"346234876"), Info(b"foobar"));
    let ct = ds.cipher_key.encrypt(b"plaintext", &nc);
    assert_eq!(ct.len(), b"plaintext".len());
    assert!(ct != b"plaintext");
    assert_eq!(ds.cipher_key.decrypt(&ct, &nc), b"plaintext");
}
