// Copyright (C) 2022 Wire Swiss GmbH <support@wire.com>
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

use proteus_traits::{PreKeyStore, ProteusErrorCode, ProteusErrorKind};
use std::{
    borrow::{Borrow, Cow},
    cmp::{Ord, Ordering},
    collections::{BTreeMap, VecDeque},
    io::{Cursor, Read, Write},
};

use crate::internal::{
    derived::{CipherKey, DerivedSecrets, MacKey},
    keys::{
        IdentityKey, IdentityKeyPair, KeyPair, PreKey, PreKeyBundle, PreKeyId, PublicKey,
        MAX_PREKEY_ID,
    },
    message::{CipherMessage, Counter, Envelope, Message, PreKeyMessage, SessionTag},
    types::{DecodeError, DecodeResult, EncodeResult, InternalError},
};

use cbor::{self, skip::Skip, Config, Decoder, Encoder};

// Root key /////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RootKey {
    key: CipherKey,
}

impl RootKey {
    #[must_use]
    pub fn from_cipher_key(k: CipherKey) -> RootKey {
        RootKey { key: k }
    }

    pub fn dh_ratchet<E>(
        &self,
        ours: &KeyPair,
        theirs: &PublicKey,
    ) -> SessionResult<(RootKey, ChainKey), E> {
        let secret = ours.secret_key.shared_secret(theirs)?;
        let dsecs = DerivedSecrets::kdf(secret.as_slice(), Some(&self.key), b"dh_ratchet")?;
        Ok((
            RootKey::from_cipher_key(dsecs.cipher_key),
            ChainKey::from_mac_key(dsecs.mac_key, Counter::zero()),
        ))
    }

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(1)?;
        e.u8(0)?;
        self.key.encode(e)
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<RootKey> {
        let n = d.object()?;
        let mut key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if key.is_none() => key = Some(CipherKey::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(RootKey {
            key: key.ok_or(DecodeError::MissingField("RootKey::key"))?,
        })
    }
}

// Chain key /////////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainKey {
    key: MacKey,
    idx: Counter,
}

impl ChainKey {
    #[must_use]
    pub fn from_mac_key(k: MacKey, idx: Counter) -> ChainKey {
        ChainKey { key: k, idx }
    }

    #[must_use]
    pub fn next(&self) -> ChainKey {
        ChainKey {
            key: MacKey::new(self.key.sign(b"1").into_bytes()),
            idx: self.idx.next(),
        }
    }

    pub fn message_keys(&self) -> Result<MessageKeys, InternalError> {
        let base = self.key.sign(b"0");
        let dsecs = DerivedSecrets::kdf_without_salt(&base, b"hash_ratchet")?;
        Ok(MessageKeys {
            cipher_key: dsecs.cipher_key,
            mac_key: dsecs.mac_key,
            counter: self.idx,
        })
    }

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0)?;
        self.key.encode(e)?;
        e.u8(1)?;
        self.idx.encode(e)
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<ChainKey> {
        let n = d.object()?;
        let mut key = None;
        let mut idx = None;
        for _ in 0..n {
            match d.u8()? {
                0 if key.is_none() => key = Some(MacKey::decode(d)?),
                1 if idx.is_none() => idx = Some(Counter::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(ChainKey {
            key: key.ok_or(DecodeError::MissingField("ChainKey::key"))?,
            idx: idx.ok_or(DecodeError::MissingField("ChainKey::idx"))?,
        })
    }
}

// Send Chain ///////////////////////////////////////////////////////////////

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SendChain {
    chain_key: ChainKey,
    ratchet_key: KeyPair,
}

impl SendChain {
    #[must_use]
    pub fn new(ck: ChainKey, rk: KeyPair) -> SendChain {
        SendChain {
            chain_key: ck,
            ratchet_key: rk,
        }
    }

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(2)?;
        e.u8(0)?;
        self.chain_key.encode(e)?;
        e.u8(1)?;
        self.ratchet_key.encode(e)
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<SendChain> {
        let n = d.object()?;
        let mut chain_key = None;
        let mut ratchet_key = None;
        for _ in 0..n {
            match d.u8()? {
                0 if chain_key.is_none() => chain_key = Some(ChainKey::decode(d)?),
                1 if ratchet_key.is_none() => ratchet_key = Some(KeyPair::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(SendChain {
            chain_key: chain_key.ok_or(DecodeError::MissingField("SendChain::chain_key"))?,
            ratchet_key: ratchet_key.ok_or(DecodeError::MissingField("SendChain::ratchet_key"))?,
        })
    }
}

// Receive Chain ////////////////////////////////////////////////////////////

const MAX_COUNTER_GAP: usize = 1000;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecvChain {
    chain_key: ChainKey,
    ratchet_key: PublicKey,
    message_keys: VecDeque<MessageKeys>,
}

impl RecvChain {
    #[must_use]
    pub fn new(ck: ChainKey, rk: PublicKey) -> RecvChain {
        RecvChain {
            chain_key: ck,
            ratchet_key: rk,
            message_keys: VecDeque::new(),
        }
    }

    fn try_message_keys<E>(
        &mut self,
        env: &Envelope,
        mesg: &CipherMessage,
    ) -> SessionResult<Vec<u8>, E> {
        let too_old = self
            .message_keys
            .get(0)
            .map_or(false, |k| k.counter > mesg.counter);

        if too_old {
            return Err(SessionError::OutdatedMessage);
        }

        let Some(i) = self
            .message_keys
            .iter()
            .position(|mk| mk.counter == mesg.counter) else {
                // ? Handles error case 209
                return Err(SessionError::DuplicateMessage);
            };

        // SAFETY: Indexing directly is safe as the `position` check above ensure we have a MessageKeys present at the index
        if !env.verify(&self.message_keys[i].mac_key) {
            // ? Handles error case 210
            return Err(SessionError::InvalidSignature);
        }

        let Some(mk) = self.message_keys.remove(i) else {
            // SAFETY: We cannot reach this codepath as: if `i` doesn't exist, we'll return `SessionError::DuplicateMessage` above
            // Thus, index `i` is always present and we cannot reach this codepath
            unreachable!()
        };

        Ok(mk.decrypt(&mesg.cipher_text))
    }

    fn stage_message_keys<E>(
        &self,
        msg: &CipherMessage,
    ) -> SessionResult<(ChainKey, MessageKeys, VecDeque<MessageKeys>), E> {
        let num = (msg.counter.value() - self.chain_key.idx.value()) as usize;

        if num > MAX_COUNTER_GAP {
            return Err(SessionError::TooDistantFuture);
        }

        let mut buf = VecDeque::with_capacity(num);
        let mut chk = self.chain_key.clone();

        for _ in 0..num {
            buf.push_back(chk.message_keys()?);
            chk = chk.next();
        }

        let mk = chk.message_keys()?;
        Ok((chk, mk, buf))
    }

    fn commit_message_keys<E>(&mut self, mut mks: VecDeque<MessageKeys>) -> SessionResult<(), E> {
        // ? Handles error code 103
        if mks.len() > MAX_COUNTER_GAP {
            return Err(SessionError::MessageKeysExceedCounterGap);
        }

        let (excess, excess_overflows) = self.message_keys.len().overflowing_add(mks.len());

        if excess_overflows {
            return Err(SessionError::OverflowingMessageKeys);
        }

        let excess = excess.saturating_sub(MAX_COUNTER_GAP);

        if excess > 0 {
            self.message_keys.drain(..excess);
        }

        self.message_keys.append(&mut mks);

        // ? Handles error code 104
        if self.message_keys.len() > MAX_COUNTER_GAP {
            return Err(SessionError::SkippedMessageKeysExceedCounterGap);
        }

        Ok(())
    }

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(3)?;
        e.u8(0)?;
        self.chain_key.encode(e)?;
        e.u8(1)?;
        self.ratchet_key.encode(e)?;
        e.u8(2)?;
        {
            e.array(self.message_keys.len())?;
            for m in &self.message_keys {
                m.encode(e)?;
            }
        }
        Ok(())
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<RecvChain> {
        let n = d.object()?;
        let mut chain_key = None;
        let mut ratchet_key = None;
        let mut message_keys = None;
        for _ in 0..n {
            match d.u8()? {
                0 if chain_key.is_none() => chain_key = Some(ChainKey::decode(d)?),
                1 if ratchet_key.is_none() => ratchet_key = Some(PublicKey::decode(d)?),
                2 if message_keys.is_none() => {
                    message_keys = Some({
                        let lv = d.array()?;
                        let mut vm = VecDeque::with_capacity(lv);
                        for _ in 0..lv {
                            vm.push_back(MessageKeys::decode(d)?);
                        }
                        vm
                    });
                }
                _ => d.skip()?,
            }
        }
        Ok(RecvChain {
            chain_key: chain_key.ok_or(DecodeError::MissingField("RecvChain::chain_key"))?,
            ratchet_key: ratchet_key.ok_or(DecodeError::MissingField("RecvChain::ratchet_key"))?,
            message_keys: message_keys.unwrap_or_default(),
        })
    }
}

// Message Keys /////////////////////////////////////////////////////////////

#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MessageKeys {
    cipher_key: CipherKey,
    mac_key: MacKey,
    counter: Counter,
}

impl MessageKeys {
    fn encrypt(&self, plain_text: &[u8]) -> Vec<u8> {
        self.cipher_key.encrypt(plain_text, self.counter.as_nonce())
    }

    fn decrypt(&self, cipher_text: &[u8]) -> Vec<u8> {
        self.cipher_key
            .decrypt(cipher_text, self.counter.as_nonce())
    }

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(3)?;
        e.u8(0)?;
        self.cipher_key.encode(e)?;
        e.u8(1)?;
        self.mac_key.encode(e)?;
        e.u8(2)?;
        self.counter.encode(e)
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<MessageKeys> {
        let n = d.object()?;
        let mut cipher_key = None;
        let mut mac_key = None;
        let mut counter = None;
        for _ in 0..n {
            match d.u8()? {
                0 if cipher_key.is_none() => cipher_key = Some(CipherKey::decode(d)?),
                1 if mac_key.is_none() => mac_key = Some(MacKey::decode(d)?),
                2 if counter.is_none() => counter = Some(Counter::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(MessageKeys {
            cipher_key: cipher_key.ok_or(DecodeError::MissingField("MessageKeys::cipher_key"))?,
            mac_key: mac_key.ok_or(DecodeError::MissingField("MessageKeys::mac_key"))?,
            counter: counter.ok_or(DecodeError::MissingField("MessageKeys::counter"))?,
        })
    }
}

// Session //////////////////////////////////////////////////////////////////

const MAX_RECV_CHAINS: usize = 5;
const MAX_SESSION_STATES: usize = 100;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Indexed<A> {
    pub idx: usize,
    pub val: A,
}

impl<A> Indexed<A> {
    pub fn new(i: usize, a: A) -> Indexed<A> {
        Indexed { idx: i, val: a }
    }
}

// Note [session_tag]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// The session tag denotes the session state which is used to encrypt
// messages. Messages contain the session tag which was used for their
// encryption, which allows the receiving end to perform an efficient
// lookup. It is imperative to ensure that the session tag *always*
// denotes a value in the session's map of session states, otherwise
// `Session::encrypt` can not succeed. The only places where we change
// it after initialisation is in `Session::insert_session_state` which
// sets it to the value of the state which is inserted.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Session<I> {
    version: u8,
    session_tag: SessionTag,
    counter: usize,
    local_identity: I,
    remote_identity: IdentityKey,
    pending_prekey: Option<(PreKeyId, PublicKey)>,
    session_states: BTreeMap<SessionTag, Indexed<SessionState>>,
}

struct AliceParams<'r> {
    alice_ident: &'r IdentityKeyPair,
    alice_base: &'r KeyPair,
    bob: &'r PreKeyBundle,
}

struct BobParams<'r> {
    bob_ident: &'r IdentityKeyPair,
    bob_prekey: KeyPair,
    alice_ident: &'r IdentityKey,
    alice_base: &'r PublicKey,
}

impl<I: Borrow<IdentityKeyPair>> Session<I> {
    pub fn init_from_prekey<E>(alice: I, pk: PreKeyBundle) -> SessionResult<Session<I>, E> {
        let alice_base = KeyPair::new(None);
        let state = SessionState::init_as_alice(&AliceParams {
            alice_ident: alice.borrow(),
            alice_base: &alice_base,
            bob: &pk,
        })?;

        let session_tag = SessionTag::new();
        let mut session = Session {
            version: 1,
            session_tag,
            counter: 0,
            local_identity: alice,
            remote_identity: pk.identity_key,
            pending_prekey: Some((pk.prekey_id, alice_base.public_key)),
            session_states: BTreeMap::new(),
        };

        session.insert_session_state(session_tag, state);
        Ok(session)
    }

    #[allow(clippy::type_complexity)]
    pub async fn init_from_message<S: proteus_traits::PreKeyStore>(
        ours: I,
        store: &mut S,
        env: &Envelope<'_>,
    ) -> SessionResult<(Session<I>, Vec<u8>), S::Error> {
        let Message::Keyed(pkmsg) = env.message() else {
            return Err(SessionError::InvalidMessage);
        };

        let mut session = Session {
            version: 1,
            session_tag: pkmsg.message.session_tag,
            counter: 0,
            local_identity: ours,
            remote_identity: (*pkmsg.identity_key).clone(),
            pending_prekey: None,
            session_states: BTreeMap::new(),
        };

        match session.new_state(store, pkmsg).await? {
            Some(mut s) => {
                let plain = s.decrypt(env, &pkmsg.message)?;
                session.insert_session_state(pkmsg.message.session_tag, s);
                if pkmsg.prekey_id != MAX_PREKEY_ID {
                    store
                        .remove(pkmsg.prekey_id.value())
                        .await
                        .map_err(SessionError::PreKeyStoreError)?;
                }
                Ok((session, plain))
            }
            None => Err(SessionError::PreKeyNotFound(pkmsg.prekey_id)),
        }
    }

    #[cfg(any(feature = "hazmat", test))]
    pub fn session_tag_mut(&mut self) -> &mut SessionTag {
        &mut self.session_tag
    }

    #[cfg(any(feature = "hazmat", test))]
    pub fn session_states_mut(&mut self) -> &mut BTreeMap<SessionTag, Indexed<SessionState>> {
        &mut self.session_states
    }

    pub fn encrypt(&mut self, plain: &[u8]) -> EncodeResult<Envelope> {
        let state = self
            .session_states
            .get_mut(&self.session_tag)
            // ? Handles error code 102
            .ok_or(InternalError::NoSessionForTag)?; // See note [session_tag]

        state.val.encrypt(
            &self.local_identity.borrow().public_key,
            &self.pending_prekey,
            self.session_tag,
            plain,
        )
    }

    pub async fn decrypt<S: PreKeyStore>(
        &mut self,
        store: &mut S,
        env: &Envelope<'_>,
    ) -> SessionResult<Vec<u8>, S::Error> {
        match *env.message() {
            Message::Plain(ref m) => self.decrypt_cipher_message(env, m),
            Message::Keyed(ref m) => {
                if *m.identity_key != self.remote_identity {
                    return Err(SessionError::RemoteIdentityChanged);
                }
                match self.decrypt_cipher_message(env, &m.message) {
                    e @ Err(SessionError::InvalidSignature | SessionError::InvalidMessage) => {
                        match self.new_state(store, m).await? {
                            Some(mut s) => {
                                let plain = s.decrypt(env, &m.message)?;
                                if m.prekey_id != MAX_PREKEY_ID {
                                    store
                                        .remove(m.prekey_id.value())
                                        .await
                                        .map_err(SessionError::PreKeyStoreError)?;
                                }
                                self.insert_session_state(m.message.session_tag, s);
                                self.pending_prekey = None;
                                Ok(plain)
                            }
                            None => e,
                        }
                    }
                    x => x,
                }
            }
        }
    }

    fn decrypt_cipher_message<E>(
        &mut self,
        env: &Envelope,
        m: &CipherMessage,
    ) -> SessionResult<Vec<u8>, E> {
        let mut s = match self.session_states.get_mut(&m.session_tag) {
            Some(s) => s.val.clone(),
            None => return Err(SessionError::InvalidMessage),
        };
        let plain = s.decrypt(env, m)?;
        self.pending_prekey = None;
        self.insert_session_state(m.session_tag, s);
        Ok(plain)
    }

    // Attempt to create a new session state based on the prekey that we
    // attempt to lookup in our prekey store. If successful we return the
    // newly created state. It is the caller's responsibility to remove the
    // prekey from the store.
    // See note [no_new_state] for those cases where no prekey has been found.
    async fn new_state<S: proteus_traits::PreKeyStore>(
        &self,
        store: &mut S,
        m: &PreKeyMessage<'_>,
    ) -> SessionResult<Option<SessionState>, S::Error> {
        let prekey_raw = store
            .prekey(m.prekey_id.value())
            .await
            // ? Handles error codes 101
            .map_err(SessionError::PreKeyStoreError)?
            .ok_or(SessionError::PreKeyNotFound(m.prekey_id))?;

        if let Ok(prekey) = PreKey::deserialise(&prekey_raw) {
            SessionState::init_as_bob(BobParams {
                bob_ident: self.local_identity.borrow(),
                bob_prekey: prekey.key_pair,
                alice_ident: &m.identity_key,
                alice_base: &m.base_key,
            })
            .map(Some)
            .map_err(Into::into)
        } else {
            Ok(None)
        }
    }

    // Here we either replace a session state we already have with a clone
    // that has ratcheted forward, or we add a new session state. In any
    // case we ensure, that the session's `session_tag` value is equal to
    // the given one.
    //
    // Note [counter_overflow]
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Theoretically the session counter--which is used to give newer session
    // states a higher number than older ones--can overflow. While unlikely,
    // we better handle this gracefully (if somewhat brutal) by clearing all
    // states and resetting the counter to 0. This means that the only session
    // state left is the one to be inserted, but if Alice and Bob do not
    // manage to agree on a session state within `usize::MAX` it is probably
    // of least concern.
    fn insert_session_state(&mut self, t: SessionTag, s: SessionState) {
        if let Some(x) = self.session_states.get_mut(&t) {
            x.val = s;
        } else {
            let (new_counter, overflowing) = self.counter.overflowing_add(1);
            let mut counter_to_insert = self.counter;
            if overflowing {
                // See note [counter_overflow]
                self.session_states.clear();
                counter_to_insert = new_counter;
            }
            self.session_states
                .insert(t, Indexed::new(counter_to_insert, s));
            self.counter = new_counter;
        }

        // See note [session_tag]
        if self.session_tag != t {
            self.session_tag = t;
        }

        // Too many states => remove the one with lowest counter value (= oldest)
        if self.session_states.len() >= MAX_SESSION_STATES {
            if let Some(session_tag) = self
                .session_states
                .iter()
                .filter(|s| s.0 != &self.session_tag)
                .min_by_key(|s| s.1.idx)
                .map(|(t, _)| *t)
            {
                self.session_states.remove(&session_tag);
            }
        }
    }

    pub fn local_identity(&self) -> &IdentityKey {
        &self.local_identity.borrow().public_key
    }

    pub fn remote_identity(&self) -> &IdentityKey {
        &self.remote_identity
    }

    pub fn serialise(&self) -> EncodeResult<Vec<u8>> {
        let mut e = Encoder::new(Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise(ident: I, b: &[u8]) -> DecodeResult<Session<I>> {
        Session::decode(ident, &mut Decoder::new(Config::default(), Cursor::new(b)))
    }

    pub fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(6)?;
        e.u8(0)?;
        e.u8(self.version)?;
        e.u8(1)?;
        self.session_tag.encode(e)?;
        e.u8(2)?;
        self.local_identity.borrow().public_key.encode(e)?;
        e.u8(3)?;
        self.remote_identity.encode(e)?;
        e.u8(4)?;
        {
            match self.pending_prekey {
                None => e.null()?,
                Some((id, ref pk)) => {
                    e.object(2)?;
                    e.u8(0)?;
                    id.encode(e)?;
                    e.u8(1)?;
                    pk.encode(e)?;
                }
            }
        }
        e.u8(5)?;
        {
            e.object(self.session_states.len())?;
            for (t, s) in &self.session_states {
                t.encode(e)?;
                s.val.encode(e)?;
            }
        }
        Ok(())
    }

    pub fn decode<R: Read + Skip>(ident: I, d: &mut Decoder<R>) -> DecodeResult<Session<I>> {
        let n = d.object()?;
        let mut version = None;
        let mut session_tag = None;
        let mut counter = 0;
        let mut remote_identity = None;
        let mut pending_prekey = None;
        let mut session_states = None;
        for _ in 0..n {
            match d.u8()? {
                0 if version.is_none() => version = Some(d.u8()?),
                1 if session_tag.is_none() => session_tag = Some(SessionTag::decode(d)?),
                2 => {
                    let li = IdentityKey::decode(d)?;
                    if ident.borrow().public_key != li {
                        return Err(DecodeError::LocalIdentityChanged(li));
                    }
                }
                3 if remote_identity.is_none() => remote_identity = Some(IdentityKey::decode(d)?),
                4 if pending_prekey.is_none() => {
                    pending_prekey = Some({
                        if let Some(n) = cbor::opt(d.object())? {
                            let mut id = None;
                            let mut pk = None;
                            for _ in 0..n {
                                match d.u8()? {
                                    0 if id.is_none() => id = Some(PreKeyId::decode(d)?),
                                    1 if pk.is_none() => pk = Some(PublicKey::decode(d)?),
                                    _ => d.skip()?,
                                }
                            }
                            Some((
                                id.ok_or(DecodeError::MissingField("Session::pending_prekey_id"))?,
                                pk.ok_or(DecodeError::MissingField("Session::pending_prekey"))?,
                            ))
                        } else {
                            None
                        }
                    });
                }
                5 if session_states.is_none() => {
                    session_states = Some({
                        let ls = d.object()?;
                        let mut rb = BTreeMap::new();
                        for _ in 0..ls {
                            let t = SessionTag::decode(d)?;
                            let s = SessionState::decode(d)?;
                            rb.insert(t, Indexed::new(counter, s));
                            counter = counter.wrapping_add(1);
                        }
                        rb
                    });
                }
                _ => d.skip()?,
            }
        }
        Ok(Session {
            version: version.ok_or(DecodeError::MissingField("Session::version"))?,
            session_tag: session_tag.ok_or(DecodeError::MissingField("Session::session_tag"))?,
            counter,
            local_identity: ident,
            remote_identity: remote_identity
                .ok_or(DecodeError::MissingField("Session::remote_identity"))?,
            pending_prekey: pending_prekey.flatten(),
            session_states: session_states
                .ok_or(DecodeError::MissingField("Session::session_states"))?,
        })
    }
}

// Session State ////////////////////////////////////////////////////////////

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionState {
    recv_chains: VecDeque<RecvChain>,
    send_chain: SendChain,
    root_key: RootKey,
    prev_counter: Counter,
}

impl SessionState {
    fn init_as_alice<E>(p: &AliceParams) -> SessionResult<SessionState, E> {
        let master_key = {
            let mut buf = Vec::new();
            buf.extend(*p.alice_ident.secret_key.shared_secret(&p.bob.public_key)?);
            buf.extend(
                *p.alice_base
                    .secret_key
                    .shared_secret(&p.bob.identity_key.public_key)?,
            );
            buf.extend(*p.alice_base.secret_key.shared_secret(&p.bob.public_key)?);
            buf
        };

        let dsecs = DerivedSecrets::kdf_without_salt(&master_key, b"handshake")?;

        // receiving chain
        let rootkey = RootKey::from_cipher_key(dsecs.cipher_key);
        let chainkey = ChainKey::from_mac_key(dsecs.mac_key, Counter::zero());

        let mut recv_chains = VecDeque::with_capacity(MAX_RECV_CHAINS + 1);
        recv_chains.push_front(RecvChain::new(chainkey, p.bob.public_key.clone()));

        // sending chain
        let send_ratchet = KeyPair::new(None);
        let (rok, chk) = rootkey.dh_ratchet(&send_ratchet, &p.bob.public_key)?;
        let send_chain = SendChain::new(chk, send_ratchet);

        Ok(SessionState {
            recv_chains,
            send_chain,
            root_key: rok,
            prev_counter: Counter::zero(),
        })
    }

    fn init_as_bob<E>(p: BobParams) -> SessionResult<SessionState, E> {
        let master_key = {
            let mut buf = Vec::new();
            buf.extend(
                *p.bob_prekey
                    .secret_key
                    .shared_secret(&p.alice_ident.public_key)?,
            );
            buf.extend(*p.bob_ident.secret_key.shared_secret(p.alice_base)?);
            buf.extend(*p.bob_prekey.secret_key.shared_secret(p.alice_base)?);
            buf
        };

        let dsecs = DerivedSecrets::kdf_without_salt(&master_key, b"handshake")?;

        // sending chain
        let rootkey = RootKey::from_cipher_key(dsecs.cipher_key);
        let chainkey = ChainKey::from_mac_key(dsecs.mac_key, Counter::zero());
        let send_chain = SendChain::new(chainkey, p.bob_prekey);

        Ok(SessionState {
            recv_chains: VecDeque::with_capacity(MAX_RECV_CHAINS + 1),
            send_chain,
            root_key: rootkey,
            prev_counter: Counter::zero(),
        })
    }

    fn ratchet<E>(&mut self, ratchet_key: PublicKey) -> SessionResult<(), E> {
        let new_ratchet = KeyPair::new(None);

        let (recv_root_key, recv_chain_key) = self
            .root_key
            .dh_ratchet(&self.send_chain.ratchet_key, &ratchet_key)?;

        let (send_root_key, send_chain_key) =
            recv_root_key.dh_ratchet(&new_ratchet, &ratchet_key)?;

        let recv_chain = RecvChain::new(recv_chain_key, ratchet_key);
        let send_chain = SendChain::new(send_chain_key, new_ratchet);
        self.root_key = send_root_key;
        self.prev_counter = self.send_chain.chain_key.idx;
        self.send_chain = send_chain;

        self.recv_chains.push_front(recv_chain);

        if self.recv_chains.len() > MAX_RECV_CHAINS {
            self.recv_chains.pop_back();
        }

        Ok(())
    }

    fn encrypt<'r>(
        self: &'r mut SessionState,
        ident: &'r IdentityKey,
        pending: &'r Option<(PreKeyId, PublicKey)>,
        tag: SessionTag,
        plain: &[u8],
    ) -> EncodeResult<Envelope> {
        let msgkeys = self.send_chain.chain_key.message_keys()?;

        let cmessage = CipherMessage {
            session_tag: tag,
            ratchet_key: Cow::Borrowed(&self.send_chain.ratchet_key.public_key),
            counter: self.send_chain.chain_key.idx,
            prev_counter: self.prev_counter,
            cipher_text: msgkeys.encrypt(plain),
        };

        let message = match *pending {
            None => Message::Plain(Box::new(cmessage)),
            Some(ref pp) => Message::Keyed(Box::new(PreKeyMessage {
                prekey_id: pp.0,
                base_key: Cow::Borrowed(&pp.1),
                identity_key: Cow::Borrowed(ident),
                message: cmessage,
            })),
        };

        let env = Envelope::new(&msgkeys.mac_key, message);
        self.send_chain.chain_key = self.send_chain.chain_key.next();
        env
    }

    fn decrypt<E>(&mut self, env: &Envelope, m: &CipherMessage) -> SessionResult<Vec<u8>, E> {
        let rchain: &mut RecvChain = match self
            .recv_chains
            .iter_mut()
            .find(|c| c.ratchet_key == *m.ratchet_key)
        {
            Some(chain) => chain,
            None => {
                self.ratchet::<E>((*m.ratchet_key).clone())?;
                &mut self.recv_chains[0]
            }
        };

        match m.counter.cmp(&rchain.chain_key.idx) {
            Ordering::Less => rchain.try_message_keys(env, m),
            Ordering::Greater => {
                let (chk, mk, mks) = rchain.stage_message_keys::<E>(m)?;
                let plain = mk.decrypt(&m.cipher_text);
                if !env.verify(&mk.mac_key) {
                    return Err(SessionError::InvalidSignature);
                }
                rchain.chain_key = chk.next();
                rchain.commit_message_keys(mks)?;
                Ok(plain)
            }
            Ordering::Equal => {
                let mks = rchain.chain_key.message_keys()?;
                let plain = mks.decrypt(&m.cipher_text);
                if !env.verify(&mks.mac_key) {
                    return Err(SessionError::InvalidSignature);
                }
                rchain.chain_key = rchain.chain_key.next();
                Ok(plain)
            }
        }
    }

    fn encode<W: Write>(&self, e: &mut Encoder<W>) -> EncodeResult<()> {
        e.object(4)?;
        e.u8(0)?;
        {
            e.array(self.recv_chains.len())?;
            for r in &self.recv_chains {
                r.encode(e)?;
            }
        }
        e.u8(1)?;
        self.send_chain.encode(e)?;
        e.u8(2)?;
        self.root_key.encode(e)?;
        e.u8(3)?;
        self.prev_counter.encode(e)?;
        // Note that key '4' was used for skipped message keys.
        Ok(())
    }

    fn decode<R: Read + Skip>(d: &mut Decoder<R>) -> DecodeResult<SessionState> {
        let n = d.object()?;
        let mut recv_chains = None;
        let mut send_chain = None;
        let mut root_key = None;
        let mut prev_counter = None;
        for _ in 0..n {
            match d.u8()? {
                0 if recv_chains.is_none() => {
                    recv_chains = Some({
                        let lr = d.array()?;
                        let mut rr = VecDeque::with_capacity(lr);
                        for _ in 0..lr {
                            rr.push_back(RecvChain::decode(d)?);
                        }
                        rr
                    });
                }
                1 if send_chain.is_none() => send_chain = Some(SendChain::decode(d)?),
                2 if root_key.is_none() => root_key = Some(RootKey::decode(d)?),
                3 if prev_counter.is_none() => prev_counter = Some(Counter::decode(d)?),
                _ => d.skip()?,
            }
        }
        Ok(SessionState {
            recv_chains: recv_chains
                .ok_or(DecodeError::MissingField("SessionState::recv_chains"))?,
            send_chain: send_chain.ok_or(DecodeError::MissingField("SessionState::send_chain"))?,
            root_key: root_key.ok_or(DecodeError::MissingField("SessionState::root_key"))?,
            prev_counter: prev_counter
                .ok_or(DecodeError::MissingField("SessionState::prev_counter"))?,
        })
    }
}

// Decrypt Error ////////////////////////////////////////////////////////////
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum SessionError<E> {
    #[error("RemoteIdentityChanged")]
    RemoteIdentityChanged,
    #[error("InvalidSignature")]
    InvalidSignature,
    #[error("InvalidMessage")]
    InvalidMessage,
    #[error("DuplicateMessage")]
    DuplicateMessage,
    #[error("TooDistantFuture")]
    TooDistantFuture,
    #[error("OutdatedMessage")]
    OutdatedMessage,
    #[error("Message keys exceed counter gap limit")]
    MessageKeysExceedCounterGap,
    #[error("Skipped message keys exceed counter gap limit")]
    SkippedMessageKeysExceedCounterGap,
    #[error("The count of message keys overflows the platform's unsigned integer type")]
    OverflowingMessageKeys,
    #[error("PreKeyStoreNotFound: {0}")]
    PreKeyNotFound(PreKeyId),
    #[error("PreKeyStoreError: {0}")]
    PreKeyStoreError(E),
    #[error("DegeneratedKey")]
    DegeneratedKey,
    #[error(transparent)]
    InternalError(#[from] InternalError),
    #[error(transparent)]
    ProteusError(crate::error::ProteusError),
}

impl<E> From<crate::error::ProteusError> for SessionError<E> {
    fn from(e: crate::error::ProteusError) -> SessionError<E> {
        match e {
            // ? Handles error code 100
            crate::error::ProteusError::Zero => Self::DegeneratedKey,
            e => Self::ProteusError(e),
        }
    }
}

impl<E> ProteusErrorCode for SessionError<E> {
    fn code(&self) -> ProteusErrorKind {
        match self {
            Self::RemoteIdentityChanged => ProteusErrorKind::RemoteIdentityChanged,
            Self::InvalidSignature => ProteusErrorKind::PreKeyMessageDoesntMatchSignature,
            Self::InvalidMessage => ProteusErrorKind::UnknownMessageFormat,
            Self::DuplicateMessage => ProteusErrorKind::DuplicateMessage,
            Self::TooDistantFuture => ProteusErrorKind::TooDistantFuture,
            Self::OutdatedMessage => ProteusErrorKind::OutdatedMessage,
            Self::MessageKeysExceedCounterGap => {
                ProteusErrorKind::MessageKeysAboveMessageChainCounterGap
            }
            Self::SkippedMessageKeysExceedCounterGap => {
                ProteusErrorKind::SkippedMessageKeysAboveMessageChainCounterGap
            }
            Self::OverflowingMessageKeys => ProteusErrorKind::IntegerOverflow,
            Self::PreKeyNotFound(_) | Self::PreKeyStoreError(_) => ProteusErrorKind::PreKeyNotFound,
            Self::DegeneratedKey => ProteusErrorKind::AssertZeroArray,
            Self::InternalError(e) => e.code(),
            Self::ProteusError(e) => e.code(),
        }
    }
}

pub type SessionResult<T, E> = Result<T, SessionError<E>>;

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::keys::gen_prekeys;
    use crate::internal::keys::{IdentityKeyPair, PreKey, PreKeyAuth, PreKeyBundle, PreKeyId};
    use crate::internal::message::{Counter, Envelope, Message, SessionTag};
    use std::borrow::Borrow;
    use std::collections::BTreeMap;
    use std::fmt;
    use std::usize;
    use std::vec::Vec;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[derive(Debug, PartialEq)]
    struct DummyError(());

    impl proteus_traits::ProteusErrorCode for DummyError {
        fn code(&self) -> ProteusErrorKind {
            ProteusErrorKind::Unknown
        }
    }

    #[derive(Debug)]
    struct TestStore {
        prekeys: Vec<PreKey>,
    }

    impl TestStore {
        pub fn prekey_slice(&self) -> &[PreKey] {
            &self.prekeys
        }
    }

    #[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
    impl proteus_traits::PreKeyStore for TestStore {
        type Error = DummyError;

        async fn prekey(
            &mut self,
            id: proteus_traits::RawPreKeyId,
        ) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
            if let Some(prekey) = self.prekeys.iter().find(|k| k.key_id.value() == id) {
                Ok(Some(prekey.serialise().unwrap()))
            } else {
                Ok(None)
            }
        }

        async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
            self.prekeys
                .iter()
                .position(|k| k.key_id.value() == id)
                .map(|ix| self.prekeys.swap_remove(ix));
            Ok(())
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq)]
    enum MsgType {
        Plain,
        Keyed,
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn pathological_case() {
        let total_size = 32;

        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();
        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), total_size as u16),
        };

        let mut alices = Vec::new();
        for pk in bob_store.prekey_slice() {
            let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), pk);
            alices.push(Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap());
        }

        assert_eq!(total_size, alices.len());

        let mut bob = Session::init_from_message(
            &bob_ident,
            &mut bob_store,
            &alices[0].encrypt(b"hello").unwrap().into_owned(),
        )
        .await
        .unwrap()
        .0;

        for a in &mut alices {
            for _ in 0..900 {
                // Inflate `MessageKeys` vector
                let _ = a.encrypt(b"hello").unwrap();
            }
            let hello_bob = a.encrypt(b"Hello Bob!").unwrap();
            assert!(bob.decrypt(&mut bob_store, &hello_bob).await.is_ok())
        }

        assert_eq!(total_size, bob.session_states.len());

        for a in &mut alices {
            assert!(bob
                .decrypt(&mut bob_store, &a.encrypt(b"Hello Bob!").unwrap())
                .await
                .is_ok());
        }
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn encrypt_decrypt() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut alice_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };
        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        alice = Session::deserialise(&alice_ident, &alice.serialise().unwrap())
            .unwrap_or_else(|e| panic!("Failed to decode session: {}", e));
        assert_eq!(
            1,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );

        let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();
        let hello_bob_delayed = alice.encrypt(b"Hello delay!").unwrap().into_owned();
        assert_eq!(1, alice.session_states.len());
        assert_eq!(
            1,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );

        let mut bob =
            assert_init_from_message(&bob_ident, &mut bob_store, &hello_bob, b"Hello Bob!").await;
        bob = Session::deserialise(&bob_ident, &bob.serialise().unwrap())
            .unwrap_or_else(|e| panic!("Failed to decode session: {}", e));
        assert_eq!(1, bob.session_states.len());
        assert_eq!(
            1,
            bob.session_states
                .get(&bob.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );
        assert_eq!(
            bob.remote_identity.fingerprint(),
            alice.local_identity.public_key.fingerprint()
        );

        let hello_alice = bob.encrypt(b"Hello Alice!").unwrap().into_owned();

        // Alice
        assert_decrypt(
            b"Hello Alice!",
            alice.decrypt(&mut alice_store, &hello_alice).await,
        );
        assert!(alice.pending_prekey.is_none());
        assert_eq!(
            2,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );
        assert_eq!(
            alice.remote_identity.fingerprint(),
            bob.local_identity.public_key.fingerprint()
        );
        let ping_bob_1 = alice.encrypt(b"Ping1!").unwrap().into_owned();
        assert_is_msg(&ping_bob_1, MsgType::Plain);
        let ping_bob_2 = alice.encrypt(b"Ping2!").unwrap().into_owned();
        assert_is_msg(&ping_bob_2, MsgType::Plain);
        assert_prev_count(&alice, 2);

        // Bob
        assert_decrypt(b"Ping1!", bob.decrypt(&mut bob_store, &ping_bob_1).await);
        assert_eq!(
            2,
            bob.session_states
                .get(&bob.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );
        assert_decrypt(b"Ping2!", bob.decrypt(&mut bob_store, &ping_bob_2).await);
        assert_eq!(
            2,
            bob.session_states
                .get(&bob.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );
        let pong_alice = bob.encrypt(b"Pong!").unwrap().into_owned();
        assert_prev_count(&bob, 1);

        // Alice
        assert_decrypt(b"Pong!", alice.decrypt(&mut alice_store, &pong_alice).await);
        assert_eq!(
            3,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );
        assert_prev_count(&alice, 2);

        // Bob (Delayed (prekey) message, decrypted with the "old" receive chain)
        assert_decrypt(
            b"Hello delay!",
            bob.decrypt(&mut bob_store, &hello_bob_delayed).await,
        );
        assert_eq!(
            2,
            bob.session_states
                .get(&bob.session_tag)
                .unwrap()
                .val
                .recv_chains
                .len()
        );
        assert_prev_count(&bob, 1);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    // @SF.Messages @TSFI.RESTfulAPI @S0.3
    async fn can_decrypt_in_wrong_order_but_can_not_decrypt_twice() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut alice_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };
        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();

        let mut bob =
            assert_init_from_message(&bob_ident, &mut bob_store, &hello_bob, b"Hello Bob!").await;

        let hello1 = bob.encrypt(b"Hello1").unwrap().into_owned();
        let hello2 = bob.encrypt(b"Hello2").unwrap().into_owned();
        let hello3 = bob.encrypt(b"Hello3").unwrap().into_owned();
        let hello4 = bob.encrypt(b"Hello4").unwrap().into_owned();
        let hello5 = bob.encrypt(b"Hello5").unwrap().into_owned();

        assert_decrypt(b"Hello2", alice.decrypt(&mut alice_store, &hello2).await);
        assert_eq!(
            1,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains[0]
                .message_keys
                .len()
        );

        assert_decrypt(b"Hello1", alice.decrypt(&mut alice_store, &hello1).await);
        assert_eq!(
            0,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains[0]
                .message_keys
                .len()
        );

        assert_decrypt(b"Hello3", alice.decrypt(&mut alice_store, &hello3).await);
        assert_eq!(
            0,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains[0]
                .message_keys
                .len()
        );

        assert_decrypt(b"Hello5", alice.decrypt(&mut alice_store, &hello5).await);
        assert_eq!(
            1,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains[0]
                .message_keys
                .len()
        );

        assert_decrypt(b"Hello4", alice.decrypt(&mut alice_store, &hello4).await);
        assert_eq!(
            0,
            alice
                .session_states
                .get(&alice.session_tag)
                .unwrap()
                .val
                .recv_chains[0]
                .message_keys
                .len()
        );

        for m in &vec![hello1, hello2, hello3, hello4, hello5] {
            assert_eq!(
                Some(SessionError::DuplicateMessage),
                alice.decrypt(&mut alice_store, m).await.err()
            );
        }
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn multiple_prekey_msgs() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob1 = alice.encrypt(b"Hello Bob1!").unwrap().into_owned();
        let hello_bob2 = alice.encrypt(b"Hello Bob2!").unwrap().into_owned();
        let hello_bob3 = alice.encrypt(b"Hello Bob3!").unwrap().into_owned();

        let mut bob =
            assert_init_from_message(&bob_ident, &mut bob_store, &hello_bob1, b"Hello Bob1!").await;
        assert_eq!(1, bob.session_states.len());
        assert_decrypt(
            b"Hello Bob2!",
            bob.decrypt(&mut bob_store, &hello_bob2).await,
        );
        assert_eq!(1, bob.session_states.len());
        assert_decrypt(
            b"Hello Bob3!",
            bob.decrypt(&mut bob_store, &hello_bob3).await,
        );
        assert_eq!(1, bob.session_states.len());
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn simultaneous_prekey_msgs() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut alice_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };
        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let alice_prekey = alice_store.prekey_slice().first().unwrap().clone();
        let alice_bundle = PreKeyBundle::new(alice_ident.public_key.clone(), &alice_prekey);

        // Initial simultaneous prekey message
        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();
        assert_is_msg(&hello_bob, MsgType::Keyed);

        let mut bob = Session::init_from_prekey::<()>(&bob_ident, alice_bundle).unwrap();
        let hello_alice = bob.encrypt(b"Hello Alice!").unwrap().into_owned();
        assert_is_msg(&hello_alice, MsgType::Keyed);

        assert_decrypt(b"Hello Bob!", bob.decrypt(&mut bob_store, &hello_bob).await);
        assert_eq!(2, bob.session_states.len());

        assert_decrypt(
            b"Hello Alice!",
            alice.decrypt(&mut alice_store, &hello_alice).await,
        );
        assert_eq!(2, alice.session_states.len());

        // Non-simultaneous answer, which results in agreement of a session.
        let greet_bob = alice.encrypt(b"That was fast!").unwrap().into_owned();
        assert_is_msg(&greet_bob, MsgType::Plain);
        assert_decrypt(
            b"That was fast!",
            bob.decrypt(&mut bob_store, &greet_bob).await,
        );

        let answer_alice = bob.encrypt(b":-)").unwrap().into_owned();
        assert_is_msg(&answer_alice, MsgType::Plain);
        assert_decrypt(b":-)", alice.decrypt(&mut alice_store, &answer_alice).await);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn simultaneous_msgs_repeated() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut alice_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };
        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let alice_prekey = alice_store.prekey_slice().first().unwrap().clone();
        let alice_bundle = PreKeyBundle::new(alice_ident.public_key.clone(), &alice_prekey);

        // Initial simultaneous prekey message
        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();
        assert_is_msg(&hello_bob, MsgType::Keyed);

        let mut bob = Session::init_from_prekey::<()>(&bob_ident, alice_bundle).unwrap();
        let hello_alice = bob.encrypt(b"Hello Alice!").unwrap().into_owned();
        assert_is_msg(&hello_alice, MsgType::Keyed);

        assert_decrypt(b"Hello Bob!", bob.decrypt(&mut bob_store, &hello_bob).await);
        assert_decrypt(
            b"Hello Alice!",
            alice.decrypt(&mut alice_store, &hello_alice).await,
        );

        // Second simultaneous message
        let echo_bob1 = alice.encrypt(b"Echo Bob1!").unwrap().into_owned();
        assert_is_msg(&echo_bob1, MsgType::Plain);

        let echo_alice1 = bob.encrypt(b"Echo Alice1!").unwrap().into_owned();
        assert_is_msg(&echo_alice1, MsgType::Plain);

        assert_decrypt(b"Echo Bob1!", bob.decrypt(&mut bob_store, &echo_bob1).await);
        assert_eq!(2, bob.session_states.len());

        assert_decrypt(
            b"Echo Alice1!",
            alice.decrypt(&mut alice_store, &echo_alice1).await,
        );
        assert_eq!(2, alice.session_states.len());

        // Third simultaneous message
        let echo_bob2 = alice.encrypt(b"Echo Bob2!").unwrap().into_owned();
        assert_is_msg(&echo_bob2, MsgType::Plain);

        let echo_alice2 = bob.encrypt(b"Echo Alice2!").unwrap().into_owned();
        assert_is_msg(&echo_alice2, MsgType::Plain);

        assert_decrypt(b"Echo Bob2!", bob.decrypt(&mut bob_store, &echo_bob2).await);
        assert_eq!(2, bob.session_states.len());

        assert_decrypt(
            b"Echo Alice2!",
            alice.decrypt(&mut alice_store, &echo_alice2).await,
        );
        assert_eq!(2, alice.session_states.len());

        // Non-simultaneous answer, which results in agreement of a session.
        let stop_bob = alice.encrypt(b"Stop it!").unwrap().into_owned();
        assert_decrypt(b"Stop it!", bob.decrypt(&mut bob_store, &stop_bob).await);

        let answer_alice = bob.encrypt(b"OK").unwrap().into_owned();
        assert_decrypt(b"OK", alice.decrypt(&mut alice_store, &answer_alice).await);
    }

    #[test]
    #[wasm_bindgen_test]
    fn enc_dec_session() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key, &bob_prekey);

        let alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let bytes = alice.serialise().unwrap();

        match Session::deserialise(&alice_ident, &bytes) {
            Err(ref e) => panic!("Failed to decode session: {}", e),
            Ok(s @ Session { .. }) => assert_eq!(bytes, s.serialise().unwrap()),
        };
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn mass_communication() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut alice_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };
        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();

        let mut bob =
            assert_init_from_message(&bob_ident, &mut bob_store, &hello_bob, b"Hello Bob!").await;

        let mut buffer = Vec::new();
        for _ in 0..1001 {
            buffer.push(bob.encrypt(b"Hello Alice!").unwrap().serialise().unwrap())
        }

        for msg in &buffer {
            assert_decrypt(
                b"Hello Alice!",
                alice
                    .decrypt(&mut alice_store, &Envelope::deserialise(msg).unwrap())
                    .await,
            );
        }

        buffer.clear();
        for _ in 0..1001 {
            let mut msg = bob.encrypt(b"Hello Alice!").unwrap().serialise().unwrap();
            msg[10] ^= 0xFF; // Flip some bits in the Mac.
            buffer.push(msg);
        }

        for msg in &buffer {
            let env = Envelope::deserialise(msg).unwrap();
            assert!(alice.decrypt(&mut alice_store, &env).await.is_err(),);
        }

        let msg = bob
            .encrypt(b"Hello Alice, after more than 1000 failed messages!")
            .unwrap()
            .serialise()
            .unwrap();
        assert_eq!(
            Err(SessionError::TooDistantFuture),
            alice
                .decrypt(&mut alice_store, &Envelope::deserialise(&msg).unwrap())
                .await,
        );
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    // @SF.Messages @TSFI.RESTfulAPI @S0.3
    async fn retry_of_init_from_message_for_the_same_message_should_return_pre_key_not_found() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob = alice.encrypt(b"Hello Bob!").unwrap();

        assert_init_from_message(&bob_ident, &mut bob_store, &hello_bob, b"Hello Bob!").await;
        // The behavior on retry depends on the PreKeyStore implementation.
        // With a PreKeyStore that eagerly deletes prekeys, like the TestStore,
        // the prekey will be gone and a retry cause an error (and thus a lost message).
        match Session::init_from_message(&bob_ident, &mut bob_store, &hello_bob).await {
            Err(SessionError::PreKeyNotFound(_)) => {} // expected
            Err(e) => panic!("{:?}", e),
            Ok(_) => panic!("Unexpected success on retrying init_from_message"),
        }
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn skipped_message_keys() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut alice_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };
        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();

        {
            let s = &alice.session_states.get(&alice.session_tag).unwrap().val;
            assert_eq!(1, s.recv_chains.len());
            assert_eq!(Counter::zero(), s.recv_chains[0].chain_key.idx);
            assert_eq!(Counter::zero().next(), s.send_chain.chain_key.idx);
            assert_eq!(0, s.recv_chains[0].message_keys.len())
        }

        let mut bob =
            assert_init_from_message(&bob_ident, &mut bob_store, &hello_bob, b"Hello Bob!").await;

        {
            // Normal exchange. Bob has created a new receive chain without skipped message keys.
            let s = &bob.session_states.get(&bob.session_tag).unwrap().val;
            assert_eq!(1, s.recv_chains.len());
            assert_eq!(Counter::zero().next(), s.recv_chains[0].chain_key.idx);
            assert_eq!(Counter::zero(), s.send_chain.chain_key.idx);
            assert_eq!(0, s.recv_chains[0].message_keys.len())
        }

        let hello_alice0 = bob.encrypt(b"Hello0").unwrap().into_owned();
        let _ = bob.encrypt(b"Hello1").unwrap().into_owned();
        let hello_alice2 = bob.encrypt(b"Hello2").unwrap().into_owned();
        assert_decrypt(
            b"Hello2",
            alice.decrypt(&mut alice_store, &hello_alice2).await,
        );

        {
            // Alice has two skipped message keys in her new receive chain.
            let s = &alice.session_states.get(&alice.session_tag).unwrap().val;
            assert_eq!(2, s.recv_chains.len());
            assert_eq!(
                Counter::zero().next().next().next(),
                s.recv_chains[0].chain_key.idx
            );
            assert_eq!(Counter::zero(), s.send_chain.chain_key.idx);
            assert_eq!(2, s.recv_chains[0].message_keys.len());
            assert_eq!(0, s.recv_chains[0].message_keys[0].counter.value());
            assert_eq!(1, s.recv_chains[0].message_keys[1].counter.value())
        }

        let hello_bob0 = alice.encrypt(b"Hello0").unwrap().into_owned();
        assert_decrypt(b"Hello0", bob.decrypt(&mut bob_store, &hello_bob0).await);

        {
            // For Bob everything is normal still. A new message from Alice means a
            // new receive chain has been created and again no skipped message keys.
            let s = &bob.session_states.get(&bob.session_tag).unwrap().val;
            assert_eq!(2, s.recv_chains.len());
            assert_eq!(Counter::zero().next(), s.recv_chains[0].chain_key.idx);
            assert_eq!(Counter::zero(), s.send_chain.chain_key.idx);
            assert_eq!(0, s.recv_chains[0].message_keys.len())
        }

        assert_decrypt(
            b"Hello0",
            alice.decrypt(&mut alice_store, &hello_alice0).await,
        );

        {
            // Alice received the first of the two missing messages. Therefore
            // only one message key is still skipped (counter value = 1).
            let s = &alice.session_states.get(&alice.session_tag).unwrap().val;
            assert_eq!(2, s.recv_chains.len());
            assert_eq!(1, s.recv_chains[0].message_keys.len());
            assert_eq!(1, s.recv_chains[0].message_keys[0].counter.value())
        }

        let hello_again0 = bob.encrypt(b"Again0").unwrap().into_owned();
        let hello_again1 = bob.encrypt(b"Again1").unwrap().into_owned();

        assert_decrypt(
            b"Again1",
            alice.decrypt(&mut alice_store, &hello_again1).await,
        );

        {
            // Bob has sent two new messages which Alice receives out of order.
            // The first one received causes a new ratchet and hence a new receive chain.
            // The second one will cause Alice to look into her skipped message keys since
            // the message index is lower than the receive chain index. This test therefore
            // ensures that skipped message keys are local to receive chains since the previous
            // receive chain still has a skipped message key with an index > 0 which would
            // cause an `OutdatedMessage` error if the vector was shared across receive chains.
            let s = &alice.session_states.get(&alice.session_tag).unwrap().val;
            assert_eq!(3, s.recv_chains.len());
            assert_eq!(1, s.recv_chains[0].message_keys.len());
            assert_eq!(1, s.recv_chains[1].message_keys.len());
            assert_eq!(0, s.recv_chains[0].message_keys[0].counter.value());
            assert_eq!(1, s.recv_chains[1].message_keys[0].counter.value());
        }

        assert_decrypt(
            b"Again0",
            alice.decrypt(&mut alice_store, &hello_again0).await,
        );
    }

    #[test]
    #[wasm_bindgen_test]
    // @SF.Messages @TSFI.RESTfulAPI @S0.3
    fn fail_on_unknown_and_invalid_prekeys_and_verify_valid_prekeys() {
        let bob_ident = IdentityKeyPair::new();
        let eve_ident = IdentityKeyPair::new();

        let eve_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };

        let eve_prekey = eve_store.prekey_slice().first().unwrap().clone();
        let mut eve_bundle = PreKeyBundle::new(eve_ident.public_key.clone(), &eve_prekey);
        let mut eve_bundle_signed = PreKeyBundle::signed(&eve_ident, &eve_prekey);

        // eve uses her own ephemeral keypair but tries to use bob's identity
        // (e.g. to benefit from existing trust relationships)
        eve_bundle_signed.identity_key = bob_ident.public_key.clone();
        eve_bundle.identity_key = bob_ident.public_key.clone();

        // non-authentic prekeys
        assert_eq!(PreKeyAuth::Unknown, eve_bundle.verify());
        assert_eq!(PreKeyAuth::Invalid, eve_bundle_signed.verify());

        // authentic prekey
        let bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 10),
        };
        let bob_prekey = bob_store.prekey_slice().first().unwrap().clone();
        let bob_bundle_signed = PreKeyBundle::signed(&bob_ident, &bob_prekey);
        assert_eq!(PreKeyAuth::Valid, bob_bundle_signed.verify());
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn session_states_limit() {
        let alice = IdentityKeyPair::new();
        let bob = IdentityKeyPair::new();

        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 500),
        };

        async fn get_bob(bob: &IdentityKeyPair, i: u16, store: &mut TestStore) -> PreKeyBundle {
            PreKeyBundle::new(
                bob.public_key.clone(),
                &PreKey::deserialise(&store.prekey(i).await.unwrap().unwrap()).unwrap(),
            )
        }

        let mut alice2bob = Session::init_from_prekey::<()>(
            &alice,
            get_bob(&bob, PreKeyId::new(1).value(), &mut bob_store).await,
        )
        .unwrap();
        let mut hello_bob = alice2bob.encrypt(b"Hello Bob!").unwrap().into_owned();
        assert_is_msg(&hello_bob, MsgType::Keyed);

        let mut bob2alice = Session::init_from_message(&bob, &mut bob_store, &hello_bob)
            .await
            .unwrap()
            .0;
        assert_eq!(1, bob2alice.session_states.len());

        // find oldest session state
        let oldest = |m: &BTreeMap<SessionTag, Indexed<SessionState>>| {
            let mut x = SessionTag::new();
            let mut n = usize::MAX;
            for (k, v) in m {
                if v.idx < n {
                    n = v.idx;
                    x = *k;
                }
            }
            x
        };

        for i in 2..500 {
            alice2bob = Session::init_from_prekey::<()>(
                &alice,
                get_bob(&bob, PreKeyId::new(i).value(), &mut bob_store).await,
            )
            .unwrap();
            hello_bob = alice2bob.encrypt(b"Hello Bob!").unwrap().into_owned();
            assert_is_msg(&hello_bob, MsgType::Keyed);

            let to_remove = oldest(&bob2alice.session_states);
            assert_decrypt(
                b"Hello Bob!",
                bob2alice.decrypt(&mut bob_store, &hello_bob).await,
            );
            let n = bob2alice.session_states.len();
            assert!(n < 100);
            if i > 99 {
                assert!(!bob2alice.session_states.contains_key(&to_remove));
            }
        }
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    // @SF.Messages @TSFI.RESTfulAPI @S0.3
    async fn fail_on_decryption_of_a_too_old_message() {
        let alice = IdentityKeyPair::new();
        let bob = IdentityKeyPair::new();

        let mut bob_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(0), 1),
        };

        let mut alice_store = TestStore {
            prekeys: gen_prekeys(PreKeyId::new(1), 1),
        };

        async fn get_bob(bob: &IdentityKeyPair, i: u16, store: &mut TestStore) -> PreKeyBundle {
            PreKeyBundle::new(
                bob.public_key.clone(),
                &PreKey::deserialise(&store.prekey(i).await.unwrap().unwrap()).unwrap(),
            )
        }

        let mut alice2bob = Session::init_from_prekey::<()>(
            &alice,
            get_bob(&bob, PreKeyId::new(1).value(), &mut bob_store).await,
        )
        .unwrap();
        let hello_bob = alice2bob.encrypt(b"Hello Bob!").unwrap().into_owned();
        assert_is_msg(&hello_bob, MsgType::Keyed);

        let mut bob2alice = Session::init_from_message(&bob, &mut bob_store, &hello_bob)
            .await
            .unwrap()
            .0;
        assert_eq!(1, bob2alice.session_states.len());

        let a2b_m1 = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();
        for _ in 0..999 {
            let _encrypted = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();
        }
        let a2b_m2 = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();

        let b_m1 = bob2alice.decrypt(&mut bob_store, &a2b_m1).await.unwrap();

        assert_eq!(b_m1, &[1, 2, 3]);

        let b2a_m1 = bob2alice.encrypt(&[1, 2, 3]).unwrap().into_owned();

        let _a_m1 = alice2bob.decrypt(&mut alice_store, &b2a_m1).await.unwrap();

        let a2b_s2e1 = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s2e1 = bob2alice.decrypt(&mut bob_store, &a2b_s2e1).await.unwrap();
        let a2b_s2e2 = bob2alice.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s2e2 = alice2bob.decrypt(&mut bob_store, &a2b_s2e2).await.unwrap();

        let a2b_s3e1 = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s3e1 = bob2alice.decrypt(&mut bob_store, &a2b_s3e1).await.unwrap();
        let a2b_s3e2 = bob2alice.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s3e2 = alice2bob.decrypt(&mut bob_store, &a2b_s3e2).await.unwrap();

        let a2b_s4e1 = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s4e1 = bob2alice.decrypt(&mut bob_store, &a2b_s4e1).await.unwrap();
        let a2b_s4e2 = bob2alice.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s4e2 = alice2bob.decrypt(&mut bob_store, &a2b_s4e2).await.unwrap();

        let a2b_s5e1 = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s5e1 = bob2alice.decrypt(&mut bob_store, &a2b_s5e1).await.unwrap();
        let a2b_s5e2 = bob2alice.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s5e2 = alice2bob.decrypt(&mut bob_store, &a2b_s5e2).await.unwrap();

        let a2b_s6e1 = alice2bob.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s6e1 = bob2alice.decrypt(&mut bob_store, &a2b_s6e1).await.unwrap();
        let a2b_s6e2 = bob2alice.encrypt(&[1, 2, 3]).unwrap().into_owned();
        let _b2a_s6e2 = alice2bob.decrypt(&mut bob_store, &a2b_s6e2).await.unwrap();

        // At this point we don't have the key material to decrypt.
        let out = bob2alice.decrypt(&mut bob_store, &a2b_m2).await;
        assert_eq!(out, Err(SessionError::TooDistantFuture));
        assert!(out.is_err());
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn replaced_prekeys() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut bob_store1 = TestStore {
            prekeys: vec![PreKey::new(PreKeyId::new(1))],
        };
        let mut bob_store2 = TestStore {
            prekeys: vec![PreKey::new(PreKeyId::new(1))],
        };

        let bob_prekey = PreKey::deserialise(
            &bob_store1
                .prekey(PreKeyId::new(1).value())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob1 = alice.encrypt(b"Hello Bob1!").unwrap().into_owned();

        let mut bob =
            assert_init_from_message(&bob_ident, &mut bob_store1, &hello_bob1, b"Hello Bob1!")
                .await;
        assert_eq!(1, bob.session_states.len());

        let hello_bob2 = alice.encrypt(b"Hello Bob2!").unwrap().into_owned();
        assert_decrypt(
            b"Hello Bob2!",
            bob.decrypt(&mut bob_store1, &hello_bob2).await,
        );
        assert_eq!(1, bob.session_states.len());

        let hello_bob3 = alice.encrypt(b"Hello Bob3!").unwrap().into_owned();
        assert_decrypt(
            b"Hello Bob3!",
            bob.decrypt(&mut bob_store2, &hello_bob3).await,
        );
        assert_eq!(1, bob.session_states.len());
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn max_counter_gap() {
        let alice_ident = IdentityKeyPair::new();
        let bob_ident = IdentityKeyPair::new();

        let mut bob_store = TestStore {
            prekeys: vec![PreKey::last_resort()],
        };

        let bob_prekey = PreKey::deserialise(
            &bob_store
                .prekey(PreKeyId::new(0xFFFF).value())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);

        let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
        let hello_bob1 = alice.encrypt(b"Hello Bob!").unwrap().into_owned();

        let mut bob =
            assert_init_from_message(&bob_ident, &mut bob_store, &hello_bob1, b"Hello Bob!").await;
        assert_eq!(1, bob.session_states.len());

        for _ in 0..1001 {
            let hello_bob2 = alice.encrypt(b"Hello Bob!").unwrap().into_owned();
            assert_decrypt(
                b"Hello Bob!",
                bob.decrypt(&mut bob_store, &hello_bob2).await,
            );
            assert_eq!(1, bob.session_states.len());
        }
    }

    fn assert_decrypt<E>(expected: &[u8], actual: SessionResult<Vec<u8>, E>)
    where
        E: fmt::Debug,
    {
        match actual {
            Ok(b) => {
                let r: &[u8] = b.as_ref();
                assert_eq!(expected, r);
            }
            Err(e) => panic!("{e:?}"),
        }
    }

    async fn assert_init_from_message<'r, S>(
        i: &'r IdentityKeyPair,
        s: &mut S,
        m: &Envelope<'_>,
        t: &[u8],
    ) -> Session<&'r IdentityKeyPair>
    where
        S: PreKeyStore,
        S::Error: fmt::Debug,
    {
        match Session::init_from_message(i, s, m).await {
            Ok((s, b)) => {
                let r: &[u8] = b.as_ref();
                assert_eq!(t, r);
                s
            }
            Err(e) => {
                unreachable!("{e:?}");
            }
        }
    }

    fn assert_prev_count<I: Borrow<IdentityKeyPair>>(s: &Session<I>, expected: u32) {
        assert_eq!(
            expected,
            s.session_states
                .get(&s.session_tag)
                .unwrap()
                .val
                .prev_counter
                .value()
        );
    }

    fn assert_is_msg(e: &Envelope, t: MsgType) {
        match *e.message() {
            Message::Plain(_) if t == MsgType::Plain => (),
            Message::Keyed(_) if t == MsgType::Keyed => {}
            _ => panic!("invalid message type"),
        }
    }
}
