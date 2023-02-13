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
#![allow(dead_code)]

pub const MSG: &[u8] = b"Hello world!";

#[derive(Debug, PartialEq)]
pub struct DummyError(());

impl proteus_traits::ProteusErrorCode for DummyError {
    fn code(&self) -> proteus_traits::ProteusErrorKind {
        proteus_traits::ProteusErrorKind::Unknown
    }
}

#[derive(Debug)]
pub struct PrekeyStore<T>(pub Vec<T>);

impl<T> Default for PrekeyStore<T> {
    fn default() -> Self {
        Self(vec![])
    }
}

impl<T> std::ops::Deref for PrekeyStore<T> {
    type Target = Vec<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for PrekeyStore<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(not(target_family = "wasm"))]
impl proteus::session::PreKeyStore for PrekeyStore<proteus::keys::PreKey> {
    type Error = DummyError;

    fn prekey(
        &mut self,
        id: proteus::keys::PreKeyId,
    ) -> Result<Option<proteus::keys::PreKey>, Self::Error> {
        Ok(self.0.iter().find(|k| k.key_id == id).cloned())
    }

    fn remove(&mut self, id: proteus::keys::PreKeyId) -> Result<(), Self::Error> {
        self.0
            .iter()
            .position(|k| k.key_id.value() == id.value())
            .map(|idx| self.0.swap_remove(idx));

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl proteus_traits::PreKeyStore for PrekeyStore<proteus_wasm::keys::PreKey> {
    type Error = DummyError;

    async fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        Ok(self
            .0
            .iter()
            .find(|k| k.key_id.value() == id)
            .map(|pk| proteus_wasm::keys::PreKey::serialise(pk).unwrap()))
    }

    async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        self.0
            .iter()
            .position(|k| k.key_id.value() == id)
            .map(|idx| self.0.swap_remove(idx));

        Ok(())
    }
}

macro_rules! impl_harness_for_crate {
    ($client:ident, $target:ident) => {
        pub struct $client {
            pub identity: $target::keys::IdentityKeyPair,
            pub prekeys: PrekeyStore<$target::keys::PreKey>,
            pub sessions: std::collections::HashMap<
                String,
                $target::session::Session<$target::keys::IdentityKeyPair>,
            >,
        }

        impl $client {
            #[must_use]
            pub fn new() -> Self {
                let identity = $target::keys::IdentityKeyPair::new();
                Self {
                    identity,
                    prekeys: Default::default(),
                    sessions: Default::default(),
                }
            }

            #[allow(dead_code)]
            pub fn fingerprint(&self) -> String {
                self.identity.public_key.fingerprint()
            }

            pub fn init_session_from_prekey_bundle_faillible(
                &mut self,
                session_id: &str,
                prekey_bundle_raw: &[u8],
            ) -> Result<(), $target::session::Error<DummyError>> {
                let bob_prekey_bundle =
                    $target::keys::PreKeyBundle::deserialise(prekey_bundle_raw).unwrap();
                let session = $target::session::Session::init_from_prekey(
                    self.identity.clone(),
                    bob_prekey_bundle,
                )?;

                self.sessions.insert(session_id.to_string(), session);

                Ok(())
            }

            pub fn init_session_from_prekey_bundle(
                &mut self,
                session_id: &str,
                prekey_bundle_raw: &[u8],
            ) {
                self.init_session_from_prekey_bundle_faillible(session_id, prekey_bundle_raw)
                    .unwrap();
            }

            pub fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Vec<u8> {
                let session = self.sessions.get_mut(session_id).unwrap();
                session.encrypt(plaintext).unwrap().serialise().unwrap()
            }

            #[allow(dead_code)]
            pub fn session(
                &mut self,
                session_id: &str,
            ) -> &mut $target::session::Session<$target::keys::IdentityKeyPair> {
                self.sessions.get_mut(session_id).unwrap()
            }

            pub fn new_prekey(&mut self) -> $target::keys::PreKeyBundle {
                let prekey_id = (self.prekeys.len() + 1 % u16::MAX as usize) as u16;
                let prekey = $target::keys::PreKey::new($target::keys::PreKeyId::new(prekey_id));
                let prekey_bundle =
                    $target::keys::PreKeyBundle::new(self.identity.public_key.clone(), &prekey);
                self.prekeys.push(prekey);
                prekey_bundle
            }

            pub fn new_prekey_with_id(&mut self, prekey_id: u16) -> $target::keys::PreKeyBundle {
                let prekey = $target::keys::PreKey::new($target::keys::PreKeyId::new(prekey_id));
                let prekey_bundle =
                    $target::keys::PreKeyBundle::new(self.identity.public_key.clone(), &prekey);
                self.prekeys.push(prekey);
                prekey_bundle
            }

            pub fn get_prekey_bundle(&self, index: usize) -> $target::keys::PreKeyBundle {
                let prekey = &self.prekeys[index];
                let prekey_bundle =
                    $target::keys::PreKeyBundle::new(self.identity.public_key.clone(), prekey);
                prekey_bundle
            }
        }
    };
}

impl_harness_for_crate!(Client, proteus_wasm);
#[cfg(not(target_family = "wasm"))]
impl_harness_for_crate!(LegacyClient, proteus);

impl Client {
    #[cfg(not(target_family = "wasm"))]
    pub fn downgrade(self) -> LegacyClient {
        let identity =
            proteus::keys::IdentityKeyPair::deserialise(&self.identity.serialise().unwrap())
                .unwrap();
        let prekeys = PrekeyStore(
            self.prekeys
                .iter()
                .map(|pk| proteus::keys::PreKey::deserialise(&pk.serialise().unwrap()).unwrap())
                .collect(),
        );

        let sessions = self
            .sessions
            .into_iter()
            .map(|(id, session)| {
                (
                    id,
                    proteus::session::Session::deserialise(
                        identity.clone(),
                        &session.serialise().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect();

        LegacyClient {
            identity,
            prekeys,
            sessions,
        }
    }

    pub async fn decrypt_faillible(
        &mut self,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, proteus_wasm::internal::session::SessionError<DummyError>> {
        let envelope = proteus_wasm::message::Envelope::deserialise(ciphertext).unwrap();
        match self.sessions.get_mut(session_id) {
            Some(session) => Ok(session.decrypt(&mut self.prekeys, &envelope).await?),
            None => Ok(self
                .init_session_from_message(session_id, ciphertext)
                .await?),
        }
    }

    pub async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Vec<u8> {
        self.decrypt_faillible(session_id, ciphertext)
            .await
            .unwrap()
    }

    pub async fn init_session_from_message(
        &mut self,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, proteus_wasm::internal::session::SessionError<DummyError>> {
        let envelope = proteus_wasm::message::Envelope::deserialise(ciphertext).unwrap();

        let (session, message) = proteus_wasm::session::Session::init_from_message(
            self.identity.clone(),
            &mut self.prekeys,
            &envelope,
        )
        .await?;

        self.sessions.insert(session_id.to_string(), session);

        Ok(message)
    }

    pub fn encrypt_with_max_counter(&mut self, session_id: &str, plaintext: &[u8]) -> Vec<u8> {
        let session = self.sessions.get_mut(session_id).unwrap();
        let mut envelope = session.encrypt(plaintext).unwrap();
        envelope.break_counter();

        envelope.serialise().unwrap()
    }
}

#[cfg(not(target_family = "wasm"))]
impl LegacyClient {
    pub fn upgrade(self) -> Client {
        let identity =
            proteus_wasm::keys::IdentityKeyPair::deserialise(&self.identity.serialise().unwrap())
                .unwrap();
        let prekeys = PrekeyStore(
            self.prekeys
                .iter()
                .map(|pk| {
                    proteus_wasm::keys::PreKey::deserialise(&pk.serialise().unwrap()).unwrap()
                })
                .collect(),
        );

        let sessions = self
            .sessions
            .into_iter()
            .map(|(id, session)| {
                (
                    id,
                    proteus_wasm::session::Session::deserialise(
                        identity.clone(),
                        &session.serialise().unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect();

        Client {
            identity,
            prekeys,
            sessions,
        }
    }

    pub fn decrypt_faillible(
        &mut self,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, proteus::session::Error<DummyError>> {
        let envelope = proteus::message::Envelope::deserialise(ciphertext).unwrap();
        match self.sessions.get_mut(session_id) {
            Some(session) => Ok(session.decrypt(&mut self.prekeys, &envelope)?),
            None => {
                let (session, message) = proteus::session::Session::init_from_message(
                    self.identity.clone(),
                    &mut self.prekeys,
                    &envelope,
                )
                .unwrap();

                self.sessions.insert(session_id.to_string(), session);

                Ok(message)
            }
        }
    }

    pub fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Vec<u8> {
        self.decrypt_faillible(session_id, ciphertext).unwrap()
    }

    pub fn init_session_from_message(
        &mut self,
        session_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, proteus::session::Error<DummyError>> {
        let envelope = proteus::message::Envelope::deserialise(ciphertext).unwrap();

        let (session, message) = proteus::session::Session::init_from_message(
            self.identity.clone(),
            &mut self.prekeys,
            &envelope,
        )
        .unwrap();

        self.sessions.insert(session_id.to_string(), session);

        Ok(message)
    }
}

impl Client {
    pub fn from_raw(sk: [u8; 64], pk: [u8; 32]) -> Self {
        Client {
            identity: unsafe {
                proteus_wasm::keys::IdentityKeyPair::from_raw_key_pair(sk, pk).unwrap()
            },
            prekeys: Default::default(),
            sessions: Default::default(),
        }
    }
}
