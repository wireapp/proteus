// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use bincode::SizeLimit;
use bincode::{EncoderWriter};
use internal::derived::{Mac, MacKey, Nonce};
use internal::keys::{IdentityKey, PreKeyId, PublicKey};
use internal::util;
use std::old_io::extensions::u64_to_be_bytes;
use std::slice::bytes::copy_memory;
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
        u64_to_be_bytes(self.0 as u64, 4, |x| {
            copy_memory(nonce.as_mut_slice(), x)
        });
        Nonce::new(nonce)
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
        binary::enc_msg(&m, &mut EncoderWriter::new(&mut v, SizeLimit::Infinite)).unwrap();

        Envelope {
            version:     Version::V1,
            mac:         k.sign(v.as_slice()),
            message:     m,
            message_enc: v
        }
    }

    pub fn verify(&self, k: &MacKey) -> bool {
        k.verify(&self.mac, self.message_enc.as_slice())
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

    pub fn decode(b: &[u8]) -> Option<Envelope> {
        util::decode(b, binary::dec_envelope).ok()
    }
}
