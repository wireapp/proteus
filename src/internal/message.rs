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
use cbor::{Config, Decoder, Encoder};
use internal::derived::{Mac, MacKey, Nonce};
use internal::keys::{IdentityKey, PreKeyId, PublicKey};
use internal::types::{DecodeError, DecodeResult, EncodeResult};
use internal::util::fmt_hex;
use sodiumoxide::randombytes;
use std::borrow::Cow;
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

    pub fn value(self) -> u32 {
        self.0
    }

    pub fn next(self) -> Counter {
        Counter(self.0 + 1)
    }

    pub fn as_nonce(self) -> Nonce {
        let mut nonce = [0; 8];
        nonce[0] = (self.0 >> 24) as u8;
        nonce[1] = (self.0 >> 16) as u8;
        nonce[2] = (self.0 >> 8) as u8;
        nonce[3] = self.0 as u8;
        Nonce::new(nonce)
    }

    pub fn encode<W: Write>(self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.u32(self.0).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Counter> {
        d.u32().map(Counter).map_err(From::from)
    }
}

// Session Tag //////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SessionTag {
    tag: [u8; 16],
}

impl SessionTag {
    pub fn new() -> SessionTag {
        let mut bytes = [0; 16];
        randombytes::randombytes_into(&mut bytes);
        SessionTag { tag: bytes }
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.bytes(&self.tag).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<SessionTag> {
        let v = d.bytes()?;
        if 16 != v.len() {
            return Err(DecodeError::InvalidArrayLen(v.len()));
        }
        let mut a = [0u8; 16];
        a[..16].clone_from_slice(&v[..16]);
        Ok(SessionTag { tag: a })
    }
}

impl fmt::Debug for SessionTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", fmt_hex(&self.tag))
    }
}

// Message //////////////////////////////////////////////////////////////////

pub enum Message<'r> {
    Plain(CipherMessage<'r>),
    Keyed(PreKeyMessage<'r>),
}

impl<'r> Message<'r> {
    fn into_owned<'s>(self) -> Message<'s> {
        match self {
            Message::Plain(m) => Message::Plain(m.into_owned()),
            Message::Keyed(m) => Message::Keyed(m.into_owned()),
        }
    }

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        match *self {
            Message::Plain(ref m) => {
                e.u8(1)?;
                m.encode(e)
            }
            Message::Keyed(ref m) => {
                e.u8(2)?;
                m.encode(e)
            }
        }
    }

    fn decode<'s, R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Message<'s>> {
        match d.u8()? {
            1 => CipherMessage::decode(d).map(Message::Plain),
            2 => PreKeyMessage::decode(d).map(Message::Keyed),
            t => Err(DecodeError::InvalidType(t, "unknown message type")),
        }
    }
}

// Prekey Message ///////////////////////////////////////////////////////////

pub struct PreKeyMessage<'r> {
    pub prekey_id: PreKeyId,
    pub base_key: Cow<'r, PublicKey>,
    pub identity_key: Cow<'r, IdentityKey>,
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

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(4)?;
        e.u8(0)?;
        self.prekey_id.encode(e)?;
        e.u8(1)?;
        self.base_key.encode(e)?;
        e.u8(2)?;
        self.identity_key.encode(e)?;
        e.u8(3)?;
        self.message.encode(e)
    }

    fn decode<'s, R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<PreKeyMessage<'s>> {
        let n = d.object()?;
        let mut prekey_id = None;
        let mut base_key = None;
        let mut identity_key = None;
        let mut message = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("PreKeyMessage::prekey_id", prekey_id, PreKeyId::decode(d)?),
                1 => uniq!("PreKeyMessage::base_key", base_key, PublicKey::decode(d)?),
                2 => uniq!(
                    "PreKeyMessage::identity_key",
                    identity_key,
                    IdentityKey::decode(d)?
                ),
                3 => uniq!("PreKeyMessage::message", message, CipherMessage::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(PreKeyMessage {
            prekey_id: to_field!(prekey_id, "PreKeyMessage::prekey_id"),
            base_key: Cow::Owned(to_field!(base_key, "PreKeyMessage::base_key")),
            identity_key: Cow::Owned(to_field!(identity_key, "PreKeyMessage::identity_key")),
            message: to_field!(message, "PreKeyMessage::message"),
        })
    }
}

// CipherMessage ////////////////////////////////////////////////////////////

pub struct CipherMessage<'r> {
    pub session_tag: SessionTag,
    pub counter: Counter,
    pub prev_counter: Counter,
    pub ratchet_key: Cow<'r, PublicKey>,
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

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(5)?;
        e.u8(0)?;
        self.session_tag.encode(e)?;
        e.u8(1)?;
        self.counter.encode(e)?;
        e.u8(2)?;
        self.prev_counter.encode(e)?;
        e.u8(3)?;
        self.ratchet_key.encode(e)?;
        e.u8(4)?;
        e.bytes(&self.cipher_text[..])?;
        Ok(())
    }

    fn decode<'s, R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<CipherMessage<'s>> {
        let n = d.object()?;
        let mut session_tag = None;
        let mut counter = None;
        let mut prev_counter = None;
        let mut ratchet_key = None;
        let mut cipher_text = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!(
                    "CipherMessage::session_tag",
                    session_tag,
                    SessionTag::decode(d)?
                ),
                1 => uniq!("CipherMessage::counter", counter, Counter::decode(d)?),
                2 => uniq!(
                    "CipherMessage::prev_counter",
                    prev_counter,
                    Counter::decode(d)?
                ),
                3 => uniq!(
                    "CipherMessage::ratchet_key",
                    ratchet_key,
                    PublicKey::decode(d)?
                ),
                4 => uniq!("CipherMessage::cipher_text", cipher_text, d.bytes()?),
                _ => d.skip()?,
            }
        }
        Ok(CipherMessage {
            session_tag: to_field!(session_tag, "CipherMessage::session_tag"),
            counter: to_field!(counter, "CipherMessage::counter"),
            prev_counter: to_field!(prev_counter, "CipherMessage::prev_counter"),
            ratchet_key: Cow::Owned(to_field!(ratchet_key, "CipherMessage::ratchet_key")),
            cipher_text: to_field!(cipher_text, "CipherMessage::cipher_text"),
        })
    }
}

// Message Envelope /////////////////////////////////////////////////////////

pub struct Envelope<'r> {
    version: u8,
    mac: Mac,
    message: Message<'r>,
    message_enc: Vec<u8>,
}

impl<'r> Envelope<'r> {
    pub fn new(k: &MacKey, m: Message<'r>) -> EncodeResult<Envelope<'r>> {
        let mut c = Cursor::new(Vec::new());
        m.encode(&mut Encoder::new(&mut c))?;

        Ok(Envelope {
            version: 1,
            mac: k.sign(c.get_ref()),
            message: m,
            message_enc: c.into_inner(),
        })
    }

    pub fn into_owned<'s>(self) -> Envelope<'s> {
        Envelope {
            version: self.version,
            mac: self.mac,
            message: self.message.into_owned(),
            message_enc: self.message_enc,
        }
    }

    pub fn verify(&self, k: &MacKey) -> bool {
        k.verify(&self.mac, &self.message_enc)
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
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise<'s>(b: &[u8]) -> DecodeResult<Envelope<'s>> {
        Envelope::decode(&mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(3)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.mac.encode(e)?;
        e.u8(2).and(e.bytes(&self.message_enc))?;
        Ok(())
    }

    pub fn decode<'s, R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<Envelope<'s>> {
        let n = d.object()?;
        let mut version = None;
        let mut mac = None;
        let mut message = None;
        let mut message_enc = None;
        for _ in 0..n {
            match d.u8()? {
                0 => uniq!("Envelope::version", version, d.u8()?),
                1 => uniq!("Envelope::mac", mac, Mac::decode(d)?),
                2 if message.is_some() => {
                    return Err(DecodeError::DuplicateField("Envelope::message"))
                }
                2 => {
                    let msg_enc = d.bytes()?;
                    message = Some(Message::decode(&mut Decoder::new(
                        Config::default(),
                        Cursor::new(&msg_enc[..]),
                    ))?);
                    message_enc = Some(msg_enc)
                }
                _ => d.skip()?,
            }
        }
        Ok(Envelope {
            version: to_field!(version, "Envelope::version"),
            message: to_field!(message, "Envelope::message"),
            message_enc: to_field!(message_enc, "Envelope::message_enc"),
            mac: to_field!(mac, "Envelope::mac"),
        })
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use internal::derived::MacKey;
    use internal::keys::{IdentityKey, KeyPair, PreKeyId};
    use std::borrow::Cow;

    #[test]
    // @SF.Messages @TSFI.RESTfulAPI
    fn envelope_created_with_MacKey_should_be_verified_with_that_key_after_serialization_deserialization() {
        let mk = MacKey::new([1; 32]);
        let bk = KeyPair::new().public_key;
        let ik = IdentityKey::new(KeyPair::new().public_key);
        let rk = KeyPair::new().public_key;

        let tg = SessionTag::new();
        let m1 = Message::Keyed(PreKeyMessage {
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
        });

        let m2 = Message::Plain(CipherMessage {
            session_tag: tg,
            counter: Counter(42),
            prev_counter: Counter(3),
            ratchet_key: Cow::Borrowed(&rk),
            cipher_text: vec![1, 2, 3, 4, 5],
        });

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
