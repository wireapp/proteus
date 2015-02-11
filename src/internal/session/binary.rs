// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use bincode::{EncoderWriter, EncodingError, DecoderReader, DecodingError};
use internal::derived::binary::*;
use internal::keys::binary::*;
use internal::message::binary::*;
use rustc_serialize::{Decodable, Decoder, Encodable};
use std::collections::RingBuf;
use std::old_io::{Buffer, Writer};
use super::*;

// Root key /////////////////////////////////////////////////////////////////

pub fn enc_root_key<W: Writer>(k: &RootKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    enc_cipher_key(&k.key, e)
}

pub fn dec_root_key<R: Buffer>(d: &mut DecoderReader<R>) -> Result<RootKey, DecodingError> {
    dec_cipher_key(d).map(|k| RootKey { key: k } )
}

// Chain key /////////////////////////////////////////////////////////////////

pub fn enc_chain_key<W: Writer>(k: &ChainKey, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_mac_key(&k.key, e));
    enc_counter(&k.idx, e)
}

pub fn dec_chain_key<R: Buffer>(d: &mut DecoderReader<R>) -> Result<ChainKey, DecodingError> {
    let k = try!(dec_mac_key(d));
    let c = try!(dec_counter(d));
    Ok(ChainKey { key: k, idx: c })
}

// Send Chain ///////////////////////////////////////////////////////////////

pub fn enc_send_chain<W: Writer>(s: &SendChain, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_chain_key(&s.chain_key, e));
    enc_keypair(&s.ratchet_key, e)
}

pub fn dec_send_chain<R: Buffer>(d: &mut DecoderReader<R>) -> Result<SendChain, DecodingError> {
    let k = try!(dec_chain_key(d));
    let c = try!(dec_keypair(d));
    Ok(SendChain { chain_key: k, ratchet_key: c })
}

// Receive Chain ////////////////////////////////////////////////////////////

pub fn enc_recv_chain<W: Writer>(r: &RecvChain, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_chain_key(&r.chain_key, e));
    enc_public_key(&r.ratchet_key, e)
}

pub fn dec_recv_chain<R: Buffer>(d: &mut DecoderReader<R>) -> Result<RecvChain, DecodingError> {
    let k = try!(dec_chain_key(d));
    let c = try!(dec_public_key(d));
    Ok(RecvChain { chain_key: k, ratchet_key: c })
}

// Message Keys /////////////////////////////////////////////////////////////

pub fn enc_msg_keys<W: Writer>(k: &MessageKeys, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_cipher_key(&k.cipher_key, e));
    try!(enc_mac_key(&k.mac_key, e));
    enc_counter(&k.counter, e)
}

pub fn dec_msg_keys<R: Buffer>(d: &mut DecoderReader<R>) -> Result<MessageKeys, DecodingError> {
    let k = try!(dec_cipher_key(d));
    let m = try!(dec_mac_key(d));
    let c = try!(dec_counter(d));
    Ok(MessageKeys { cipher_key: k, mac_key: m, counter: c })
}

// Version //////////////////////////////////////////////////////////////////

fn enc_session_version<W: Writer>(_: &Version, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    1u32.encode(e)
}

fn dec_session_version<R: Buffer>(d: &mut DecoderReader<R>) -> Result<Version, DecodingError> {
    match try!(Decodable::decode(d)) {
        1u32 => Ok(Version::V1),
        vers => Err(d.error(format!("Unknow session version {}", vers).as_slice()))
    }
}

// Session //////////////////////////////////////////////////////////////////

pub fn enc_session<W: Writer>(s: &Session, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(enc_session_version(&s.version, e));
    try!(enc_identity_keypair(&s.local_identity, e));
    try!(enc_identity_key(&s.remote_identity, e));
    match s.pending_prekey {
        None           => try!(1u32.encode(e)),
        Some((id, pk)) => {
            try!(2u32.encode(e));
            try!(enc_prekey_id(&id, e));
            try!(enc_public_key(&pk, e))
        }
    }
    try!(s.session_states.len().encode(e));
    for t in s.session_states.iter() {
        try!(enc_session_state(t, e))
    }
    Ok(())
}

pub fn dec_session<R: Buffer>(d: &mut DecoderReader<R>) -> Result<Session, DecodingError> {
    let vs = try!(dec_session_version(d));
    let li = try!(dec_identity_keypair(d));
    let ri = try!(dec_identity_key(d));
    let pp = match try!(Decodable::decode(d)) {
        1u32 => None,
        2u32 => {
            let id = try!(dec_prekey_id(d));
            let pk = try!(dec_public_key(d));
            Some((id, pk))
        }
        _ => return Err(d.error("Invalid pending prekeys"))
    };
    let ls: usize = try!(Decodable::decode(d));
    let mut rb = RingBuf::with_capacity(ls);
    for _ in 0 .. ls {
        rb.push_back(try!(dec_session_state(d)))
    }
    Ok(Session {
        version:         vs,
        local_identity:  li,
        remote_identity: ri,
        pending_prekey:  pp,
        session_states:  rb
    })
}

// Session State ////////////////////////////////////////////////////////////

pub fn enc_session_state<W: Writer>(s: &SessionState, e: &mut EncoderWriter<W>) -> Result<(), EncodingError> {
    try!(s.recv_chains.len().encode(e));
    for r in s.recv_chains.iter() {
        try!(enc_recv_chain(r, e))
    }
    try!(enc_send_chain(&s.send_chain, e));
    try!(enc_root_key(&s.root_key, e));
    try!(enc_counter(&s.prev_counter, e));
    try!(s.skipped_msgkeys.len().encode(e));
    for m in s.skipped_msgkeys.iter() {
        try!(enc_msg_keys(m, e))
    }
    Ok(())
}

pub fn dec_session_state<R: Buffer>(d: &mut DecoderReader<R>) -> Result<SessionState, DecodingError> {
    let lr: usize = try!(Decodable::decode(d));
    let mut rr = RingBuf::with_capacity(lr);
    for _ in 0 .. lr {
        rr.push_back(try!(dec_recv_chain(d)))
    }
    let sc = try!(dec_send_chain(d));
    let rk = try!(dec_root_key(d));
    let ct = try!(dec_counter(d));
    let lv: usize = try!(Decodable::decode(d));
    let mut vm = RingBuf::with_capacity(lv);
    for _ in 0 .. lv {
        vm.push_front(try!(dec_msg_keys(d)))
    }
    Ok(SessionState {
        recv_chains:     rr,
        send_chain:      sc,
        root_key:        rk,
        prev_counter:    ct,
        skipped_msgkeys: vm
    })
}
