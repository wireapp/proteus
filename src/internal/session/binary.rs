// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Decoder, Encoder};
use internal::keys::IdentityKeyPair;
use internal::message::binary::*;
use internal::derived::binary::*;
use internal::keys::binary::*;
use internal::util::{DecodeError, DecodeResult, EncodeResult};
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use super::*;

// Root key /////////////////////////////////////////////////////////////////

pub fn enc_root_key<W: Write>(k: &RootKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    enc_cipher_key(&k.key, e)
}

pub fn dec_root_key<R: Read>(d: &mut Decoder<R>) -> DecodeResult<RootKey> {
    dec_cipher_key(d).map(|k| RootKey { key: k } )
}

// Chain key /////////////////////////////////////////////////////////////////

pub fn enc_chain_key<W: Write>(k: &ChainKey, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_mac_key(&k.key, e));
    enc_counter(&k.idx, e)
}

pub fn dec_chain_key<R: Read>(d: &mut Decoder<R>) -> DecodeResult<ChainKey> {
    let k = try!(dec_mac_key(d));
    let c = try!(dec_counter(d));
    Ok(ChainKey { key: k, idx: c })
}

// Send Chain ///////////////////////////////////////////////////////////////

pub fn enc_send_chain<W: Write>(s: &SendChain, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_chain_key(&s.chain_key, e));
    enc_keypair(&s.ratchet_key, e)
}

pub fn dec_send_chain<R: Read>(d: &mut Decoder<R>) -> DecodeResult<SendChain> {
    let k = try!(dec_chain_key(d));
    let c = try!(dec_keypair(d));
    Ok(SendChain { chain_key: k, ratchet_key: c })
}

// Receive Chain ////////////////////////////////////////////////////////////

pub fn enc_recv_chain<W: Write>(r: &RecvChain, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_chain_key(&r.chain_key, e));
    enc_public_key(&r.ratchet_key, e)
}

pub fn dec_recv_chain<R: Read>(d: &mut Decoder<R>) -> DecodeResult<RecvChain> {
    let k = try!(dec_chain_key(d));
    let c = try!(dec_public_key(d));
    Ok(RecvChain { chain_key: k, ratchet_key: c })
}

// Message Keys /////////////////////////////////////////////////////////////

pub fn enc_msg_keys<W: Write>(k: &MessageKeys, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_cipher_key(&k.cipher_key, e));
    try!(enc_mac_key(&k.mac_key, e));
    enc_counter(&k.counter, e)
}

pub fn dec_msg_keys<R: Read>(d: &mut Decoder<R>) -> DecodeResult<MessageKeys> {
    let k = try!(dec_cipher_key(d));
    let m = try!(dec_mac_key(d));
    let c = try!(dec_counter(d));
    Ok(MessageKeys { cipher_key: k, mac_key: m, counter: c })
}

// Version //////////////////////////////////////////////////////////////////

fn enc_session_version<W: Write>(v: &Version, e: &mut Encoder<W>) -> EncodeResult<()> {
    match *v {
        Version::V1 => e.u16(1).map_err(From::from)
    }
}

fn dec_session_version<R: Read>(d: &mut Decoder<R>) -> DecodeResult<Version> {
    match try!(d.u16()) {
        1 => Ok(Version::V1),
        v => Err(DecodeError::InvalidVersion(format!("unknow session version {}", v)))
    }
}

// Session //////////////////////////////////////////////////////////////////

pub fn enc_session<W: Write>(s: &Session, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_session_version(&s.version, e));
    try!(enc_session_tag(&s.session_tag, e));
    try!(enc_identity_key(&s.local_identity.public_key, e));
    try!(enc_identity_key(&s.remote_identity, e));
    match s.pending_prekey {
        None           => try!(e.bool(false)),
        Some((id, pk)) => {
            try!(e.bool(true));
            try!(enc_prekey_id(&id, e));
            try!(enc_public_key(&pk, e))
        }
    }
    try!(e.u32(s.session_states.len() as u32));
    for t in s.session_states.values() {
        try!(enc_session_state(&t.val, e))
    }
    Ok(())
}

pub fn dec_session<'r, R: Read>(ident: &'r IdentityKeyPair, d: &mut Decoder<R>) -> DecodeResult<Session<'r>> {
    let vs = try!(dec_session_version(d));
    let tg = try!(dec_session_tag(d));
    let li = try!(dec_identity_key(d));
    if li != ident.public_key {
        return Err(DecodeError::LocalIdentityChanged(li))
    }
    let ri = try!(dec_identity_key(d));
    let pp = match try!(d.bool()) {
        false => None,
        true  => {
            let id = try!(dec_prekey_id(d));
            let pk = try!(dec_public_key(d));
            Some((id, pk))
        }
    };
    let ls = try!(d.u32());
    let mut rb = BTreeMap::new();
    let mut counter = 0;
    for _ in 0 .. ls {
        let s = try!(dec_session_state(d));
        rb.insert(s.session_tag.clone(), Indexed::new(counter, s));
        counter = counter + 1
    }
    Ok(Session {
        version:         vs,
        session_tag:     tg,
        counter:         counter,
        local_identity:  ident,
        remote_identity: ri,
        pending_prekey:  pp,
        session_states:  rb
    })
}

// Session State ////////////////////////////////////////////////////////////

pub fn enc_session_state<W: Write>(s: &SessionState, e: &mut Encoder<W>) -> EncodeResult<()> {
    try!(enc_session_tag(&s.session_tag, e));
    try!(e.u32(s.recv_chains.len() as u32));
    for r in s.recv_chains.iter() {
        try!(enc_recv_chain(r, e))
    }
    try!(enc_send_chain(&s.send_chain, e));
    try!(enc_root_key(&s.root_key, e));
    try!(enc_counter(&s.prev_counter, e));
    try!(e.u32(s.skipped_msgkeys.len() as u32));
    for m in s.skipped_msgkeys.iter() {
        try!(enc_msg_keys(m, e))
    }
    Ok(())
}

pub fn dec_session_state<R: Read>(d: &mut Decoder<R>) -> DecodeResult<SessionState> {
    let tg = try!(dec_session_tag(d));
    let lr = try!(d.u32());
    let mut rr = VecDeque::with_capacity(lr as usize);
    for _ in 0 .. lr {
        rr.push_back(try!(dec_recv_chain(d)))
    }
    let sc = try!(dec_send_chain(d));
    let rk = try!(dec_root_key(d));
    let ct = try!(dec_counter(d));
    let lv = try!(d.u32());
    let mut vm = VecDeque::with_capacity(lv as usize);
    for _ in 0 .. lv {
        vm.push_back(try!(dec_msg_keys(d)))
    }
    Ok(SessionState {
        session_tag:     tg,
        recv_chains:     rr,
        send_chain:      sc,
        root_key:        rk,
        prev_counter:    ct,
        skipped_msgkeys: vm
    })
}
