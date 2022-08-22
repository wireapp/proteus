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

use crate::internal::{
    derived::{Mac, MacKey},
    keys::{IdentityKey, PreKeyId, PublicKey},
    types::{DecodeResult, EncodeResult},
    util::fmt_hex,
};
use std::{borrow::Cow, fmt};

use super::util::{cbor_deserialize, cbor_serialize};

// Counter ////////////////////////////////////////////////////////////////////
#[derive(
    minicbor::Encode, minicbor::Decode, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug,
)]
#[cbor(transparent)]
pub struct Counter(#[cbor(n(0), with = "minicbor::bytes")] u32);

impl Counter {
    pub fn zero() -> Counter {
        Counter(0)
    }

    pub fn value(self) -> u32 {
        self.0
    }

    pub fn next(self) -> Counter {
        Counter(self.0 + 1)
    }

    pub fn as_nonce(self) -> zeroize::Zeroizing<[u8; 8]> {
        let mut nonce = [0; 8];
        nonce[0] = (self.0 >> 24) as u8;
        nonce[1] = (self.0 >> 16) as u8;
        nonce[2] = (self.0 >> 8) as u8;
        nonce[3] = self.0 as u8;
        zeroize::Zeroizing::new(nonce)
    }
}

// Session Tag //////////////////////////////////////////////////////////////
#[derive(
    minicbor::Encode, minicbor::Decode, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default,
)]
#[cbor(transparent)]
pub struct SessionTag {
    #[cbor(n(0), with = "minicbor::bytes")]
    tag: [u8; 16],
}

impl SessionTag {
    pub fn new() -> SessionTag {
        let mut bytes = [0; 16];
        use rand::{RngCore as _, SeedableRng as _};
        let mut rng = rand_chacha::ChaCha12Rng::from_entropy();
        rng.fill_bytes(&mut bytes);
        SessionTag { tag: bytes }
    }
}

impl fmt::Debug for SessionTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", fmt_hex(&self.tag))
    }
}

// Message //////////////////////////////////////////////////////////////////
#[derive(minicbor::Encode, minicbor::Decode)]
pub enum Message<'r> {
    #[n(0)]
    Plain(#[n(1)] Box<CipherMessage<'r>>),
    #[n(1)]
    Keyed(#[n(2)] Box<PreKeyMessage<'r>>),
}

impl<'r> Message<'r> {
    fn into_owned<'s>(self) -> Message<'s> {
        match self {
            Message::Plain(m) => Message::Plain(Box::new(m.into_owned())),
            Message::Keyed(m) => Message::Keyed(Box::new(m.into_owned())),
        }
    }
}

// Prekey Message ///////////////////////////////////////////////////////////
#[derive(minicbor::Encode, minicbor::Decode)]
pub struct PreKeyMessage<'r> {
    #[n(0)]
    pub prekey_id: PreKeyId,
    #[b(1)]
    pub base_key: Cow<'r, PublicKey>,
    #[b(2)]
    pub identity_key: Cow<'r, IdentityKey>,
    #[b(3)]
    pub message: CipherMessage<'r>,
}

impl<'r> PreKeyMessage<'r> {
    fn into_owned<'s>(self) -> PreKeyMessage<'s> {
        PreKeyMessage {
            prekey_id: self.prekey_id,
            base_key: Cow::Owned(self.base_key.into_owned()),
            identity_key: Cow::Owned(self.identity_key.into_owned()),
            message: self.message.into_owned(),
        }
    }
}

// CipherMessage ////////////////////////////////////////////////////////////

#[derive(minicbor::Encode, minicbor::Decode)]
pub struct CipherMessage<'r> {
    #[n(0)]
    pub session_tag: SessionTag,
    #[n(1)]
    pub counter: Counter,
    #[n(2)]
    pub prev_counter: Counter,
    #[b(3)]
    pub ratchet_key: Cow<'r, PublicKey>,
    #[cbor(b(4), with = "minicbor::bytes")]
    pub cipher_text: Vec<u8>,
}

impl<'r> CipherMessage<'r> {
    fn into_owned<'s>(self) -> CipherMessage<'s> {
        CipherMessage {
            session_tag: self.session_tag,
            counter: self.counter,
            prev_counter: self.prev_counter,
            ratchet_key: Cow::Owned(self.ratchet_key.into_owned()),
            cipher_text: self.cipher_text,
        }
    }
}

// Message Envelope /////////////////////////////////////////////////////////

#[derive(minicbor::Encode, minicbor::Decode)]
pub struct Envelope<'r> {
    #[n(0)]
    version: u8,
    #[n(1)]
    mac: Mac,
    #[n(2)]
    message: Message<'r>,
}

impl<'r> Envelope<'r> {
    pub fn new(k: &MacKey, m: Message<'r>) -> EncodeResult<Envelope<'r>> {
        let c = cbor_serialize(&m)?;

        Ok(Envelope {
            version: 1,
            mac: k.sign(&c),
            message: m,
        })
    }

    pub fn into_owned<'s>(self) -> Envelope<'s> {
        Envelope {
            version: self.version,
            mac: self.mac,
            message: self.message.into_owned(),
        }
    }

    pub fn verify(&self, k: &MacKey) -> bool {
        match cbor_serialize(&self.message) {
            Ok(message_enc) => k.verify(&self.mac, &message_enc),
            Err(_) => false,
        }
    }

    pub fn version(&self) -> u16 {
        u16::from(self.version)
    }

    pub fn mac(&self) -> &Mac {
        &self.mac
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        cbor_serialize(self)
    }

    pub fn deserialise<'s>(b: &[u8]) -> DecodeResult<Envelope<'s>> {
        cbor_deserialize(b)
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::derived::MacKey;
    use crate::internal::keys::{IdentityKey, KeyPair, PreKeyId};
    use std::borrow::Cow;
    use wasm_bindgen_test::*;

    #[test]
    #[wasm_bindgen_test]
    // @SF.Messages @TSFI.RESTfulAPI @S0.3
    fn envelope_created_with_mac_key_should_be_verified_with_that_key_after_serialization_deserialization(
    ) {
        let mk = MacKey::new([1; 32]);
        let bk = KeyPair::new().public_key;
        let ik = IdentityKey::new(KeyPair::new().public_key);
        let rk = KeyPair::new().public_key;

        let tg = SessionTag::new();
        let m1 = Message::Keyed(Box::new(PreKeyMessage {
            prekey_id: PreKeyId::new(42),
            base_key: Cow::Borrowed(&bk),
            identity_key: Cow::Borrowed(&ik),
            message: CipherMessage {
                session_tag: tg,
                counter: Counter(42),
                prev_counter: Counter(43),
                ratchet_key: Cow::Borrowed(&rk),
                cipher_text: vec![1, 2, 3, 4],
            },
        }));

        let m2 = Message::Plain(Box::new(CipherMessage {
            session_tag: tg,
            counter: Counter(42),
            prev_counter: Counter(3),
            ratchet_key: Cow::Borrowed(&rk),
            cipher_text: vec![1, 2, 3, 4, 5],
        }));

        let env1 = Envelope::new(&mk, m1).unwrap();
        let env2 = Envelope::new(&mk, m2).unwrap();

        let env1_bytes = env1.serialise().unwrap();
        let env2_bytes = env2.serialise().unwrap();

        match Envelope::deserialise(&env1_bytes) {
            Err(ref e) => panic!("Failed to decode envelope: {}", e),
            Ok(e @ Envelope { .. }) => {
                assert!(e.verify(&mk));
                assert_eq!(&env1_bytes[..], &env1.serialise().unwrap()[..]);
            }
        }

        match Envelope::deserialise(&env2_bytes) {
            Err(ref e) => panic!("Failed to decode envelope: {}", e),
            Ok(e @ Envelope { .. }) => {
                assert!(e.verify(&mk));
                assert_eq!(&env2_bytes[..], &env2.serialise().unwrap()[..]);
            }
        }
    }
}
