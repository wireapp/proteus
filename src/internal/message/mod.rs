// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use byteorder::{BigEndian, WriteBytesExt};
use bincode::EncoderWriter;
use internal::derived::{Mac, MacKey, Nonce};
use internal::keys::{IdentityKey, PreKeyId, PublicKey};
use internal::util::{self, DecodeError};
use rustc_serialize::hex::ToHex;
use std::cmp::{Ord, Ordering};
use std::fmt;
use std::slice::bytes;
use std::vec::Vec;

pub mod binary;

// Version ////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq)]
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

pub struct SessionTag { tag: [u8; 64] }

impl SessionTag {
    pub fn new(prekey: &PublicKey, base: &PublicKey) -> SessionTag {
        let mut v = [0; 64];
        bytes::copy_memory(prekey.fingerprint_bytes(), &mut v);
        bytes::copy_memory(base.fingerprint_bytes(), &mut v[32 ..]);
        SessionTag { tag: v }
    }
}

impl Clone for SessionTag {
    fn clone(&self) -> SessionTag {
        SessionTag { tag: self.tag }
    }
}

impl fmt::Debug for SessionTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self.tag.to_hex())
    }
}

impl PartialEq for SessionTag {
    fn eq(&self, other: &SessionTag) -> bool {
        self.tag.as_ref() == other.tag.as_ref()
    }
}

impl Eq for SessionTag {}

impl PartialOrd for SessionTag {
    fn partial_cmp(&self, other: &SessionTag) -> Option<Ordering> {
        self.tag.as_ref().partial_cmp(other.tag.as_ref())
    }
}

impl Ord for SessionTag {
    fn cmp(&self, other: &SessionTag) -> Ordering {
        self.tag.as_ref().cmp(other.tag.as_ref())
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
    pub fn new(k: &MacKey, m: Message) -> Envelope {
        let mut v = Vec::new();
        binary::enc_msg(&m, &mut EncoderWriter::new(&mut v)).unwrap();

        Envelope {
            version:     Version::V1,
            mac:         k.sign(&v),
            message:     m,
            message_enc: v
        }
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

    pub fn encode(&self) -> Vec<u8> {
        util::encode(self, binary::enc_envelope).unwrap()
    }

    pub fn decode(b: &[u8]) -> Result<Envelope, DecodeError> {
        util::decode(b, binary::dec_envelope).map_err(From::from)
    }
}
