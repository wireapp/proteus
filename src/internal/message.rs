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
    types::{DecodeError, DecodeResult, EncodeResult},
    util::fmt_hex,
};
use cbor::{skip::Skip, Config, Decoder, Encoder};
use std::{
    borrow::Cow,
    fmt,
    io::{Cursor, Read, Write},
    vec::Vec,
};

// Counter ////////////////////////////////////////////////////////////////////

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct Counter(u32);

impl Counter {
    #[must_use]
    pub fn zero() -> Counter {
        Counter(0)
    }

    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn next(self) -> Counter {
        Counter(self.0 + 1)
    }

    pub fn next_in_place(&mut self) {
        self.0 += 1;
    }

    #[must_use]
    pub fn as_nonce(self) -> zeroize::Zeroizing<[u8; 8]> {
        let mut nonce = [0; 8];
        nonce[0] = (self.0 >> 24) as u8;
        nonce[1] = (self.0 >> 16) as u8;
        nonce[2] = (self.0 >> 8) as u8;
        nonce[3] = self.0 as u8;
        zeroize::Zeroizing::new(nonce)
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
pub struct SessionTag([u8; 16]);

impl SessionTag {
    #[must_use]
    pub fn new() -> SessionTag {
        let bytes = crate::internal::keys::rand_bytes_array::<16>(None);
        SessionTag(*bytes)
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.bytes(&self.0).map_err(From::from)
    }

    pub fn decode<R: Read>(d: &mut Decoder<R>) -> DecodeResult<SessionTag> {
        let v = d.bytes()?;
        if 16 != v.len() {
            return Err(DecodeError::InvalidArrayLen(v.len()));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&v[..16]);
        Ok(SessionTag(a))
    }
}

impl fmt::Debug for SessionTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{:?}", fmt_hex(&self.0))
    }
}

// Message //////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum Message<'r> {
    Plain(Box<CipherMessage<'r>>),
    Keyed(Box<PreKeyMessage<'r>>),
}

impl<'r> Message<'r> {
    fn into_owned<'s>(self) -> Message<'s> {
        match self {
            Message::Plain(m) => Message::Plain(Box::new(m.into_owned())),
            Message::Keyed(m) => Message::Keyed(Box::new(m.into_owned())),
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
            1 => CipherMessage::decode(d).map(|m| Message::Plain(Box::new(m))),
            2 => PreKeyMessage::decode(d).map(|m| Message::Keyed(Box::new(m))),
            t => Err(DecodeError::InvalidType(t, "unknown message type")),
        }
    }
}

// Prekey Message ///////////////////////////////////////////////////////////

#[derive(Debug)]
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
                0 if prekey_id.is_none() => prekey_id = Some(PreKeyId::decode(d)?),
                1 if base_key.is_none() => base_key = Some(PublicKey::decode(d)?),
                2 if identity_key.is_none() => identity_key = Some(IdentityKey::decode(d)?),
                3 if message.is_none() => message = Some(CipherMessage::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(PreKeyMessage {
            prekey_id: prekey_id.ok_or(DecodeError::MissingField("PreKeyMessage::prekey_id"))?,
            base_key: Cow::Owned(
                base_key.ok_or(DecodeError::MissingField("PreKeyMessage::base_key"))?,
            ),
            identity_key: Cow::Owned(
                identity_key.ok_or(DecodeError::MissingField("PreKeyMessage::identity_key"))?,
            ),
            message: message.ok_or(DecodeError::MissingField("PreKeyMessage::message"))?,
        })
    }
}

// CipherMessage ////////////////////////////////////////////////////////////

#[derive(Debug)]
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
                0 if session_tag.is_none() => session_tag = Some(SessionTag::decode(d)?),
                1 if counter.is_none() => counter = Some(Counter::decode(d)?),
                2 if prev_counter.is_none() => prev_counter = Some(Counter::decode(d)?),
                3 if ratchet_key.is_none() => ratchet_key = Some(PublicKey::decode(d)?),
                4 if cipher_text.is_none() => cipher_text = Some(d.bytes()?),
                _ => d.skip()?,
            }
        }
        Ok(CipherMessage {
            session_tag: session_tag
                .ok_or(DecodeError::MissingField("CipherMessage::session_tag"))?,
            counter: counter.ok_or(DecodeError::MissingField("CipherMessage::counter"))?,
            prev_counter: prev_counter
                .ok_or(DecodeError::MissingField("CipherMessage::prev_counter"))?,
            ratchet_key: Cow::Owned(
                ratchet_key.ok_or(DecodeError::MissingField("CipherMessage::ratchet_key"))?,
            ),
            cipher_text: cipher_text
                .ok_or(DecodeError::MissingField("CipherMessage::cipher_text"))?,
        })
    }
}

// Message Envelope /////////////////////////////////////////////////////////

#[derive(Debug)]
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

    #[must_use]
    pub fn into_owned<'s>(self) -> Envelope<'s> {
        Envelope {
            version: self.version,
            mac: self.mac,
            message: self.message.into_owned(),
            message_enc: self.message_enc,
        }
    }

    #[must_use]
    pub fn verify(&self, k: &MacKey) -> bool {
        k.verify(&self.mac, &self.message_enc)
    }

    #[must_use]
    pub fn version(&self) -> u16 {
        u16::from(self.version)
    }

    #[must_use]
    pub fn mac(&self) -> &Mac {
        &self.mac
    }

    #[must_use]
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
        e.u8(2)?;
        e.bytes(&self.message_enc)?;
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
                0 if version.is_none() => version = Some(d.u8()?),
                1 if mac.is_none() => mac = Some(Mac::decode(d)?),
                2 if message.is_some() => {
                    return Err(DecodeError::DuplicateField("Envelope::message"))
                }
                2 => {
                    let msg_enc = d.bytes()?;
                    message = Some(Message::decode(&mut Decoder::new(
                        Config::default(),
                        Cursor::new(&msg_enc[..]),
                    ))?);
                    message_enc = Some(msg_enc);
                }
                _ => d.skip()?,
            }
        }
        Ok(Envelope {
            version: version.ok_or(DecodeError::MissingField("Envelope::version"))?,
            message: message.ok_or(DecodeError::MissingField("Envelope::message"))?,
            message_enc: message_enc.ok_or(DecodeError::MissingField("Envelope::message_enc"))?,
            mac: mac.ok_or(DecodeError::MissingField("Envelope::mac"))?,
        })
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::{
        derived::MacKey,
        keys::{IdentityKey, KeyPair, PreKeyId},
    };
    use std::borrow::Cow;
    use wasm_bindgen_test::wasm_bindgen_test;

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
