// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use byteorder::{BigEndian, WriteBytesExt};
use cbor::{Config, Decoder, Encoder};
use internal::derived::{Mac, MacKey, Nonce};
use internal::keys::{IdentityKey, PreKeyId, PublicKey, rand_bytes};
use internal::util::{DecodeResult, EncodeResult};
use rustc_serialize::hex::ToHex;
use std::fmt;
use std::io::Cursor;
use std::vec::Vec;

pub mod binary;

// Version ////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version { V1 }

// Counter ////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Counter(u32);

impl Counter {
    pub fn zero() -> Counter {
        Counter(0)
    }

    pub fn value(&self) -> u32 {
        self.0
    }

    pub fn next(&self) -> Counter {
        Counter(self.0 + 1)
    }

    pub fn as_nonce(&self) -> Nonce {
        let mut nonce = [0; 24];
        nonce.as_mut().write_u32::<BigEndian>(self.0).unwrap();
        Nonce::new(nonce)
    }
}

// Session Tag //////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionTag { tag: Vec<u8> }

impl SessionTag {
    pub fn new() -> SessionTag {
        SessionTag { tag: rand_bytes(16) }
    }
}

impl fmt::Debug for SessionTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self.tag.to_hex())
    }
}

// Message //////////////////////////////////////////////////////////////////

pub enum Message {
    Plain(CipherMessage),
    Keyed(PreKeyMessage)
}

// Prekey Message ///////////////////////////////////////////////////////////

pub struct PreKeyMessage {
    pub prekey_id:    PreKeyId,
    pub base_key:     PublicKey,
    pub identity_key: IdentityKey,
    pub message:      CipherMessage
}

// CipherMessage ////////////////////////////////////////////////////////////

pub struct CipherMessage {
    pub session_tag:  SessionTag,
    pub counter:      Counter,
    pub prev_counter: Counter,
    pub ratchet_key:  PublicKey,
    pub cipher_text:  Vec<u8>
}

// Message Envelope /////////////////////////////////////////////////////////

pub struct Envelope {
    version:     Version,
    mac:         Mac,
    message:     Message,
    message_enc: Vec<u8>
}

impl Envelope {
    pub fn new(k: &MacKey, m: Message) -> EncodeResult<Envelope> {
        let mut c = Cursor::new(Vec::new());
        try!(binary::enc_msg(&m, &mut Encoder::new(&mut c)));

        Ok(Envelope {
            version:     Version::V1,
            mac:         k.sign(c.get_ref()),
            message:     m,
            message_enc: c.into_inner()
        })
    }

    pub fn verify(&self, k: &MacKey) -> bool {
        k.verify(&self.mac, &self.message_enc)
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn mac(&self) -> &Mac {
        &self.mac
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn encode(&self) -> EncodeResult<Vec<u8>> {
        let mut c = Cursor::new(Vec::new());
        try!(binary::enc_envelope(self, &mut Encoder::new(&mut c)));
        Ok(c.into_inner())
    }

    pub fn decode(b: &[u8]) -> DecodeResult<Envelope> {
        binary::dec_envelope(&mut Decoder::new(Config::default(), b))
    }
}
