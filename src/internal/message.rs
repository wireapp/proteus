// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use byteorder::{BigEndian, ByteOrder};
use cbor::{Config, Decoder, Encoder};
use cbor::skip::Skip;
use internal::derived::{Mac, MacKey, Nonce};
use internal::keys::{IdentityKey, PreKeyId, PublicKey, rand_bytes};
use internal::util::{DecodeError, DecodeResult, EncodeResult, fmt_hex};
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::vec::Vec;

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
        let mut nonce = [0; 8];
        BigEndian::write_u32(&mut nonce, self.0);
        Nonce::new(nonce)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.u32(self.0).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Counter> {
        d.u32().map(Counter).map_err(From::from)
    }
}

// Session Tag //////////////////////////////////////////////////////////////

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionTag { tag: Vec<u8> }

impl SessionTag {
    pub fn new() -> SessionTag {
        SessionTag { tag: rand_bytes(16) }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.bytes(&self.tag[..]).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<SessionTag> {
        d.bytes().map(|v| SessionTag { tag: v }).map_err(From::from)
    }
}

impl fmt::Debug for SessionTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", fmt_hex(&self.tag))
    }
}

// Message //////////////////////////////////////////////////////////////////

pub enum Message {
    Plain(CipherMessage),
    Keyed(PreKeyMessage)
}

impl Message {
    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        match *self {
            Message::Plain(ref m) => {
                try!(e.u8(1));
                m.encode(e)
            }
            Message::Keyed(ref m) => {
                try!(e.u8(2));
                m.encode(e)
            }
        }
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Message> {
        match try!(d.u8()) {
            1 => CipherMessage::decode(d).map(Message::Plain),
            2 => PreKeyMessage::decode(d).map(Message::Keyed),
            t => Err(DecodeError::InvalidMessage(format!("unknown message type {}", t)))
        }
    }
}

// Prekey Message ///////////////////////////////////////////////////////////

pub struct PreKeyMessage {
    pub prekey_id:    PreKeyId,
    pub base_key:     PublicKey,
    pub identity_key: IdentityKey,
    pub message:      CipherMessage
}

impl PreKeyMessage {
    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(4));
        try!(e.u8(0)); try!(self.prekey_id.encode(e));
        try!(e.u8(1)); try!(self.base_key.encode(e));
        try!(e.u8(2)); try!(self.identity_key.encode(e));
        try!(e.u8(3)); self.message.encode(e)
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKeyMessage> {
        let n = try!(d.object());
        let mut prekey_id    = None;
        let mut base_key     = None;
        let mut identity_key = None;
        let mut message      = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => prekey_id    = Some(try!(PreKeyId::decode(d))),
                1 => base_key     = Some(try!(PublicKey::decode(d))),
                2 => identity_key = Some(try!(IdentityKey::decode(d))),
                3 => message      = Some(try!(CipherMessage::decode(d))),
                _ => try!(d.skip())
            }
        }
        Ok(PreKeyMessage {
            prekey_id:    to_field!(prekey_id, "PreKeyMessage::prekey_id"),
            base_key:     to_field!(base_key, "PreKeyMessage::base_key"),
            identity_key: to_field!(identity_key, "PreKeyMessage::identity_key"),
            message:      to_field!(message, "PreKeyMessage::message")
        })
    }
}

// CipherMessage ////////////////////////////////////////////////////////////

pub struct CipherMessage {
    pub session_tag:  SessionTag,
    pub counter:      Counter,
    pub prev_counter: Counter,
    pub ratchet_key:  PublicKey,
    pub cipher_text:  Vec<u8>
}

impl CipherMessage {
    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(5));
        try!(e.u8(0)); try!(self.session_tag.encode(e));
        try!(e.u8(1)); try!(self.counter.encode(e));
        try!(e.u8(2)); try!(self.prev_counter.encode(e));
        try!(e.u8(3)); try!(self.ratchet_key.encode(e));
        try!(e.u8(4)); try!(e.bytes(&self.cipher_text[..]));
        Ok(())
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<CipherMessage> {
        let n = try!(d.object());
        let mut session_tag  = None;
        let mut counter      = None;
        let mut prev_counter = None;
        let mut ratchet_key  = None;
        let mut cipher_text  = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => session_tag  = Some(try!(SessionTag::decode(d))),
                1 => counter      = Some(try!(Counter::decode(d))),
                2 => prev_counter = Some(try!(Counter::decode(d))),
                3 => ratchet_key  = Some(try!(PublicKey::decode(d))),
                4 => cipher_text  = Some(try!(d.bytes())),
                _ => try!(d.skip())
            }
        }
        Ok(CipherMessage {
            session_tag:  to_field!(session_tag, "CipherMessage::session_tag"),
            counter:      to_field!(counter, "CipherMessage::counter"),
            prev_counter: to_field!(prev_counter, "CipherMessage::prev_counter"),
            ratchet_key:  to_field!(ratchet_key, "CipherMessage::ratchet_key"),
            cipher_text:  to_field!(cipher_text, "CipherMessage::cipher_text")
        })
    }
}

// Message Envelope /////////////////////////////////////////////////////////

pub struct Envelope {
    version:     u8,
    mac:         Mac,
    message:     Message,
    message_enc: Vec<u8>
}

impl Envelope {
    pub fn new(k: &MacKey, m: Message) -> EncodeResult<Envelope> {
        let mut c = Cursor::new(Vec::new());
        try!(m.encode(&mut Encoder::new(&mut c)));

        Ok(Envelope {
            version:     1,
            mac:         k.sign(c.get_ref()),
            message:     m,
            message_enc: c.into_inner()
        })
    }

    pub fn verify(&self, k: &MacKey) -> bool {
        k.verify(&self.mac, &self.message_enc)
    }

    pub fn version(&self) -> u16 {
        self.version as u16
    }

    pub fn mac(&self) -> &Mac {
        &self.mac
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        try!(self.encode(&mut e));
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(b: &[u8]) -> DecodeResult<Envelope> {
        Envelope::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        try!(e.object(3));
        try!(e.u8(0)); try!(e.u8(self.version));
        try!(e.u8(1)); try!(self.mac.encode(e));
        try!(e.u8(2).and(e.bytes(&self.message_enc)));
        Ok(())
    }

    pub fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Envelope> {
        let n = try!(d.object());
        let mut version     = None;
        let mut mac         = None;
        let mut message     = None;
        let mut message_enc = None;
        for _ in 0 .. n {
            match try!(d.u8()) {
                0 => version = Some(try!(d.u8())),
                1 => mac     = Some(try!(Mac::decode(d))),
                2 => {
                    let msg_enc = try!(d.bytes());
                    message     = Some(try!(Message::decode(&mut Decoder::new(Config::default(), Cursor::new(&msg_enc[..])))));
                    message_enc = Some(msg_enc)
                }
                _ => try!(d.skip())
            }
        }
        Ok(Envelope {
            version:     to_field!(version, "Envelope::version"),
            message:     to_field!(message, "Envelope::message"),
            message_enc: to_field!(message_enc, "Envelope::message_enc"),
            mac:         to_field!(mac, "Envelope::mac")
        })
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use internal::derived::MacKey;
    use internal::keys::{KeyPair, PreKeyId, IdentityKey};
    use super::*;

    #[test]
    fn enc_dec_envelope() {
        let mk = MacKey::new([1; 32]);
        let bk = KeyPair::new().public_key;
        let ik = IdentityKey::new(KeyPair::new().public_key);
        let rk = KeyPair::new().public_key;

        let tg = SessionTag::new();
        let m1 = Message::Keyed(PreKeyMessage {
            prekey_id:    PreKeyId::new(42),
            base_key:     bk,
            identity_key: ik,
            message:      CipherMessage {
                session_tag:  tg.clone(),
                counter:      Counter(42),
                prev_counter: Counter(43),
                ratchet_key:  rk,
                cipher_text:  vec![1, 2, 3, 4]
            }
        });

        let m2 = Message::Plain(CipherMessage {
            session_tag:  tg,
            counter:      Counter(42),
            prev_counter: Counter(3),
            ratchet_key:  rk,
            cipher_text:  vec![1, 2, 3, 4, 5]
        });

        let env1 = Envelope::new(&mk, m1).unwrap();
        let env2 = Envelope::new(&mk, m2).unwrap();

        let env1_bytes = env1.serialise().unwrap();
        let env2_bytes = env2.serialise().unwrap();

        match Envelope::deserialise(&env1_bytes) {
            Err(ref e)         => panic!("Failed to decode envelope: {}", e),
            Ok(e@Envelope{..}) => {
                assert!(e.verify(&mk));
                assert_eq!(&env1_bytes[..], &env1.serialise().unwrap()[..]);
            }
        }

        match Envelope::deserialise(&env2_bytes) {
            Err(ref e)         => panic!("Failed to decode envelope: {}", e),
            Ok(e@Envelope{..}) => {
                assert!(e.verify(&mk));
                assert_eq!(&env2_bytes[..], &env2.serialise().unwrap()[..]);
            }
        }
    }
}
