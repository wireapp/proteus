// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use bincode;
use bincode::{EncoderWriter, EncodingError, DecoderReader, DecodingError};
use internal::derived::binary::*;
use internal::keys::binary::*;
use internal::util::Array64;
use rustc_serialize::{Decodable, Decoder, Encodable};
use std::io::{BufRead, Write};
use std::vec::Vec;
use super::*;

// SessionTag ////////////////////////////////////////////////////////////////

pub fn enc_session_tag<W: Write>(s: &SessionTag, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    s.tag.encode(e)
}

pub fn dec_session_tag<R: BufRead>(d: &mut DecoderReader<R>) -> Result<SessionTag, DecodingError> {
    Array64::decode(d).map(|v| SessionTag { tag: v.array })
}

// Version ///////////////////////////////////////////////////////////////////

pub fn enc_msg_version<W: Write>(_: &Version, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    1u32.encode(e)
}

pub fn dec_msg_version<R: BufRead>(d: &mut DecoderReader<R>) -> Result<Version, DecodingError> {
    match try!(Decodable::decode(d)) {
        1u32 => Ok(Version::V1),
        vers => Err(d.error(&format!("Unknow session version {}", vers)))
    }
}

// Counter ///////////////////////////////////////////////////////////////////

pub fn enc_counter<W: Write>(c: &Counter, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    c.0.encode(e)
}

pub fn dec_counter<R: BufRead>(d: &mut DecoderReader<R>) -> Result<Counter, DecodingError> {
    Decodable::decode(d).map(Counter)
}

// Message ///////////////////////////////////////////////////////////////////

pub fn enc_msg<W: Write>(msg: &Message, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    match *msg {
        Message::Plain(ref m) => {
            try!(1u32.encode(e));
            enc_cipher_msg(m, e)
        }
        Message::Keyed(ref m) => {
            try!(2u32.encode(e));
            enc_prekey_msg(m, e)
        }
    }
}

pub fn dec_msg<R: BufRead>(d: &mut DecoderReader<R>) -> Result<Message, DecodingError> {
    match try!(Decodable::decode(d)) {
        1u32 => dec_cipher_msg(d).map(Message::Plain),
        2u32 => dec_prekey_msg(d).map(Message::Keyed),
        tag  => Err(d.error(&format!("Unknow message type {}", tag)))
    }
}

// Prekey Message ////////////////////////////////////////////////////////////

pub fn enc_prekey_msg<W: Write>(msg: &PreKeyMessage, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_prekey_id(&msg.prekey_id, e));
    try!(enc_public_key(&msg.base_key, e));
    try!(enc_identity_key(&msg.identity_key, e));
    enc_cipher_msg(&msg.message, e)
}

pub fn dec_prekey_msg<R: BufRead>(d: &mut DecoderReader<R>) -> Result<PreKeyMessage, DecodingError> {
    let pid = try!(dec_prekey_id(d));
    let bky = try!(dec_public_key(d));
    let iky = try!(dec_identity_key(d));
    let msg = try!(dec_cipher_msg(d));
    Ok(PreKeyMessage {
        prekey_id:    pid,
        base_key:     bky,
        identity_key: iky,
        message:      msg
    })
}

// CipherMessage /////////////////////////////////////////////////////////////

pub fn enc_cipher_msg<W: Write>(m: &CipherMessage, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_session_tag(&m.session_tag, e));
    try!(enc_counter(&m.counter, e));
    try!(enc_counter(&m.prev_counter, e));
    try!(enc_public_key(&m.ratchet_key, e));
    m.cipher_text.encode(e)
}

pub fn dec_cipher_msg<R: BufRead>(d: &mut DecoderReader<R>) -> Result<CipherMessage, DecodingError> {
    let tag = try!(dec_session_tag(d));
    let ctr = try!(dec_counter(d));
    let pct = try!(dec_counter(d));
    let rky = try!(dec_public_key(d));
    let txt = try!(Decodable::decode(d));
    Ok(CipherMessage {
        session_tag:  tag,
        counter:      ctr,
        prev_counter: pct,
        ratchet_key:  rky,
        cipher_text:  txt
    })
}

// Message Envelope //////////////////////////////////////////////////////////

pub fn enc_envelope<W: Write>(x: &Envelope, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_msg_version(&x.version, e));
    try!(enc_mac(&x.mac, e));
    x.message_enc.encode(e)
}

pub fn dec_envelope<R: BufRead>(d: &mut DecoderReader<R>) -> Result<Envelope, DecodingError> {
    let version = try!(dec_msg_version(d));
    let mac     = try!(dec_mac(d));
    let msg_enc: Vec<u8> = try!(Decodable::decode(d));
    match version {
        Version::V1 => {
            let msg = {
                let mut msl = msg_enc.as_ref();
                let mut drd = DecoderReader::new(&mut msl, bincode::SizeLimit::Infinite);
                try!(dec_msg(&mut drd))
            };
            Ok(Envelope {
                version:     version,
                message:     msg,
                message_enc: msg_enc,
                mac:         mac
            })
        }
    }
}

// Tests /////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use internal::derived::MacKey;
    use internal::keys::{KeyPair, PreKeyId, IdentityKey};
    use internal::message::{Counter, Message, PreKeyMessage};
    use internal::message::{CipherMessage, Envelope, SessionTag};

    #[test]
    fn enc_dec_envelope() {
        let mk = MacKey::new([1; 32]);
        let bk = KeyPair::new().public_key;
        let ik = IdentityKey::new(KeyPair::new().public_key);
        let rk = KeyPair::new().public_key;

        let tg = SessionTag::new(&bk, &rk);
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

        let env1 = Envelope::new(&mk, m1);
        let env2 = Envelope::new(&mk, m2);

        let env1_bytes = env1.encode();
        let env2_bytes = env2.encode();

        match Envelope::decode(&env1_bytes) {
            Err(ref e)         => panic!("Failed to decode envelope: {}", e),
            Ok(e@Envelope{..}) => {
                assert!(e.verify(&mk));
                assert_eq!(env1_bytes, env1.encode());
            }
        }

        match Envelope::decode(&env2_bytes) {
            Err(ref e)         => panic!("Failed to decode envelope: {}", e),
            Ok(e@Envelope{..}) => {
                assert!(e.verify(&mk));
                assert_eq!(env2_bytes, env2.encode());
            }
        }
    }
}
