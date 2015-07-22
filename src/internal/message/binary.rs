// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Config, Decoder, Encoder};
use internal::derived::binary::*;
use internal::keys::binary::*;
use internal::util::{DecodeError, DecodeResult, EncodeResult};
use std::io::{Cursor, Read, Write};
use super::*;

// SessionTag ////////////////////////////////////////////////////////////////

pub fn enc_session_tag<W: Write>(s: &SessionTag, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.bytes(&s.tag[..]).map_err(From::from)
}

pub fn dec_session_tag<R: Read>(d: &mut Decoder<R>) -> DecodeResult<SessionTag> {
    d.bytes().map(|v| SessionTag { tag: v }).map_err(From::from)
}

// Version ///////////////////////////////////////////////////////////////////

pub fn enc_msg_version<W: Write>(v: Version, e: &mut Encoder<W>) -> EncodeResult<()> {
    match v {
        Version::V1 => e.u16(1).map_err(From::from)
    }
}

pub fn dec_msg_version<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Version> {
    match try!(d.u16()) {
        1 => Ok(Version::V1),
        v => Err(DecodeError::InvalidVersion(format!("unknow message version {}", v)))
    }
}

// Counter ///////////////////////////////////////////////////////////////////

pub fn enc_counter<W: Write>(c: &Counter, e: &mut Encoder<W>) -> EncodeResult<()> {
    e.u32(c.0).map_err(From::from)
}

pub fn dec_counter<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Counter> {
    d.u32().map(Counter).map_err(From::from)
}

// Message ///////////////////////////////////////////////////////////////////

pub fn enc_msg<W: Write>(msg: &Message, e: &mut Encoder<W>) -> EncodeResult<()> {
    match *msg {
        Message::Plain(ref m) => {
            try!(e.u32(1));
            enc_cipher_msg(m, e)
        }
        Message::Keyed(ref m) => {
            try!(e.u32(2));
            enc_prekey_msg(m, e)
        }
    }
}

pub fn dec_msg<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Message> {
    match try!(d.u32()) {
        1 => dec_cipher_msg(d).map(Message::Plain),
        2 => dec_prekey_msg(d).map(Message::Keyed),
        t => Err(DecodeError::InvalidMessage(format!("unknown message type {}", t)))
    }
}

// Prekey Message ////////////////////////////////////////////////////////////

pub fn enc_prekey_msg<W: Write>(msg: &PreKeyMessage, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_prekey_id(&msg.prekey_id, e));
    try!(enc_public_key(&msg.base_key, e));
    try!(enc_identity_key(&msg.identity_key, e));
    enc_cipher_msg(&msg.message, e)
}

pub fn dec_prekey_msg<R: Read>(d: &mut Decoder<R>) -> DecodeResult<PreKeyMessage> {
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

pub fn enc_cipher_msg<W: Write>(m: &CipherMessage, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_session_tag(&m.session_tag, e));
    try!(enc_counter(&m.counter, e));
    try!(enc_counter(&m.prev_counter, e));
    try!(enc_public_key(&m.ratchet_key, e));
    e.bytes(&m.cipher_text[..]).map_err(From::from)
}

pub fn dec_cipher_msg<R: Read>(d: &mut Decoder<R>) -> DecodeResult<CipherMessage> {
    let tag = try!(dec_session_tag(d));
    let ctr = try!(dec_counter(d));
    let pct = try!(dec_counter(d));
    let rky = try!(dec_public_key(d));
    let txt = try!(d.bytes());
    Ok(CipherMessage {
        session_tag:  tag,
        counter:      ctr,
        prev_counter: pct,
        ratchet_key:  rky,
        cipher_text:  txt
    })
}

// Message Envelope //////////////////////////////////////////////////////////

pub fn enc_envelope<W: Write>(x: &Envelope, e: &mut Encoder<W>) -> EncodeResult<()> {
    match x.version {
        Version::V1 => {
            try!(e.array(3));
            try!(enc_msg_version(x.version, e));
            try!(enc_mac(&x.mac, e));
            e.bytes(&x.message_enc).map_err(From::from)
        }
    }
}

pub fn dec_envelope<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Envelope> {
    let n = try!(d.array());
    let v = try!(dec_msg_version(d));
    match v {
        Version::V1 => {
            if n != 3 {
                return Err(DecodeError::InvalidArrayLen(n))
            }
            let mac     = try!(dec_mac(d));
            let msg_enc = try!(d.bytes());
            let msg = {
                let mut rdr = Cursor::new(&msg_enc[..]);
                let mut drd = Decoder::new(Config::default(), &mut rdr);
                try!(dec_msg(&mut drd))
            };
            Ok(Envelope {
                version:     v,
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

        let env1_bytes = env1.encode().unwrap();
        let env2_bytes = env2.encode().unwrap();

        match Envelope::decode(&env1_bytes) {
            Err(ref e)         => panic!("Failed to decode envelope: {}", e),
            Ok(e@Envelope{..}) => {
                assert!(e.verify(&mk));
                assert_eq!(&env1_bytes[..], &env1.encode().unwrap()[..]);
            }
        }

        match Envelope::decode(&env2_bytes) {
            Err(ref e)         => panic!("Failed to decode envelope: {}", e),
            Ok(e@Envelope{..}) => {
                assert!(e.verify(&mk));
                assert_eq!(&env2_bytes[..], &env2.encode().unwrap()[..]);
            }
        }
    }
}
