#![cfg(all(test, not(target_family = "wasm")))]

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

impl proteus::session::PreKeyStore for PrekeyStore<proteus::keys::PreKey> {
    type Error = ();

    fn prekey(&mut self, id: proteus::keys::PreKeyId) -> Result<Option<proteus::keys::PreKey>, ()> {
        Ok(self.0.iter().find(|k| k.key_id == id).cloned())
    }

    fn remove(&mut self, id: proteus::keys::PreKeyId) -> Result<(), ()> {
        self.0
            .iter()
            .position(|k| k.key_id == id)
            .map(|idx| self.0.swap_remove(idx));

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl proteus_traits::PreKeyStore for PrekeyStore<proteus_wasm::keys::PreKey> {
    type Error = ();

    async fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, ()> {
        Ok(self
            .0
            .iter()
            .find(|k| k.key_id.value() == id)
            .map(|pk| proteus_wasm::keys::PreKey::serialise(pk).unwrap()))
    }

    async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), ()> {
        self.0
            .iter()
            .position(|k| k.key_id.value() == id)
            .map(|idx| self.0.swap_remove(idx));

        Ok(())
    }
}

macro_rules! impl_harness_for_crate {
    ($store:ident, $client:ident, $target:ident) => {
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

            pub fn init_session_from_prekey_bundle(
                &mut self,
                session_id: &str,
                prekey_bundle_raw: &[u8],
            ) {
                let bob_prekey_bundle =
                    $target::keys::PreKeyBundle::deserialise(prekey_bundle_raw).unwrap();
                let session = $target::session::Session::init_from_prekey::<()>(
                    self.identity.clone(),
                    bob_prekey_bundle,
                )
                .unwrap();

                self.sessions.insert(session_id.to_string(), session);
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

            pub fn get_prekey_bundle(&self, index: usize) -> $target::keys::PreKeyBundle {
                let prekey = &self.prekeys[index];
                let prekey_bundle =
                    $target::keys::PreKeyBundle::new(self.identity.public_key.clone(), prekey);
                prekey_bundle
            }
        }
    };
}

impl_harness_for_crate!(TestStore, Client, proteus_wasm);
impl_harness_for_crate!(TestStore, LegacyClient, proteus);

impl Client {
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

    pub async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Vec<u8> {
        let envelope = proteus_wasm::message::Envelope::deserialise(ciphertext).unwrap();
        match self.sessions.get_mut(session_id) {
            Some(session) => session.decrypt(&mut self.prekeys, &envelope).await.unwrap(),
            None => {
                let (session, message) = proteus_wasm::session::Session::init_from_message(
                    self.identity.clone(),
                    &mut self.prekeys,
                    &envelope,
                )
                .await
                .unwrap();

                self.sessions.insert(session_id.to_string(), session);

                message
            }
        }
    }
}

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

    pub fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Vec<u8> {
        let envelope = proteus::message::Envelope::deserialise(ciphertext).unwrap();
        match self.sessions.get_mut(session_id) {
            Some(session) => session.decrypt(&mut self.prekeys, &envelope).unwrap(),
            None => {
                let (session, message) = proteus::session::Session::init_from_message(
                    self.identity.clone(),
                    &mut self.prekeys,
                    &envelope,
                )
                .unwrap();

                self.sessions.insert(session_id.to_string(), session);

                message
            }
        }
    }
}

impl Client {
    pub fn from_raw(sk: [u8; 64], pk: [u8; 32]) -> Self {
        Client {
            identity: unsafe { proteus_wasm::keys::IdentityKeyPair::from_raw_key_pair(sk, pk) },
            prekeys: Default::default(),
            sessions: Default::default(),
        }
    }
}

const MSG: &[u8] = b"Hello world!";

mod serialization {
    use super::*;
    use pretty_assertions::{assert_eq, assert_str_eq};

    fn get_client_pair() -> (Client, LegacyClient) {
        assert!(proteus_wasm::init());
        assert!(proteus::init());

        let mut alice_legacy = LegacyClient::new();
        let mut sk = [0u8; 64];
        sk.copy_from_slice(&alice_legacy.identity.secret_key.as_slice()[..64]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&alice_legacy.identity.public_key.public_key.as_slice()[..32]);
        let mut alice = Client::from_raw(sk, pk);

        for _ in 0..10 {
            alice_legacy.new_prekey();
        }

        let alice_legacy_prekeys = alice_legacy
            .prekeys
            .iter()
            .map(|pk| pk.serialise().unwrap());

        for pk in alice_legacy_prekeys {
            alice
                .prekeys
                .push(proteus_wasm::keys::PreKey::deserialise(&pk).unwrap());
        }

        (alice, alice_legacy)
    }

    #[test]
    fn serialize_interop_identity_keypair() {
        let (alice, alice_legacy) = get_client_pair();
        let identity_legacy_ser = alice_legacy.identity.serialise().unwrap();
        let identity_ser = alice.identity.serialise().unwrap();

        let identity_legacy: ciborium::value::Value =
            ciborium::de::from_reader(&identity_legacy_ser[..]).unwrap();

        let identity: ciborium::value::Value =
            ciborium::de::from_reader(&identity_ser[..]).unwrap();

        assert_eq!(identity_legacy, identity);

        assert_str_eq!(hex::encode(identity_legacy_ser), hex::encode(identity_ser),);
    }

    #[test]
    fn serialize_interop_cryptobox_identity() {
        let (alice, alice_legacy) = get_client_pair();
        let identity_legacy =
            cryptobox::Identity::Sec(std::borrow::Cow::Owned(alice_legacy.identity.clone()));
        let identity =
            proteus_wasm::identity::Identity::Sec(std::borrow::Cow::Owned(alice.identity.clone()));

        let identity_legacy_ser = identity_legacy.serialise().unwrap();
        let identity_ser = identity.serialise().unwrap();

        assert_eq!(identity_legacy_ser, identity_ser);

        let cryptobox::Identity::Sec(identity_new_into_legacy) =
        cryptobox::Identity::deserialise(&identity_ser).unwrap() else {
            panic!("Wrong identity type: 2.0 -> 1.0");
        };
        let proteus_wasm::identity::Identity::Sec(identity_legacy_into_new) =
        proteus_wasm::identity::Identity::deserialise(&identity_legacy_ser).unwrap() else {
            panic!("Wrong identity type: 1.0 -> 2.0")
        };

        assert_eq!(
            identity_new_into_legacy.secret_key.as_slice(),
            alice.identity.secret_key.as_slice(),
        );

        assert_eq!(
            identity_new_into_legacy.public_key.public_key.as_slice(),
            alice.identity.public_key.public_key.as_slice(),
        );

        assert_eq!(
            identity_legacy_into_new.secret_key.as_slice(),
            alice_legacy.identity.secret_key.as_slice(),
        );

        assert_eq!(
            identity_legacy_into_new.public_key.public_key.as_slice(),
            alice_legacy.identity.public_key.public_key.as_slice(),
        );
    }

    #[test]
    fn serialize_interop_prekey() {
        let (alice, alice_legacy) = get_client_pair();

        let prekey = &alice.prekeys[0];
        let prekey_legacy = &alice_legacy.prekeys[0];

        // Check if prekeys serialize the same
        assert_eq!(
            prekey_legacy.serialise().unwrap(),
            prekey.serialise().unwrap(),
        );
    }

    #[test]
    fn serialize_interop_prekey_bundle() {
        let (alice, alice_legacy) = get_client_pair();

        // Check if prekeybundles serialize the same
        let alice_bundle = alice.get_prekey_bundle(0);
        let alice_legacy_bundle = alice_legacy.get_prekey_bundle(0);

        assert_eq!(
            alice_legacy_bundle.serialise().unwrap(),
            alice_bundle.serialise().unwrap(),
        );
    }

    #[test]
    fn serialize_interop_session() {
        let (alice, alice_legacy) = get_client_pair();

        // Start a session with `bob` from both `alice` and `alice_legacy` and check if `Sessions` are also compatible
        let mut bob_legacy = LegacyClient::new();
        let bob_bundle_for_alice_legacy = bob_legacy.new_prekey();

        let alice_legacy_bob = proteus::session::Session::init_from_prekey::<()>(
            &alice_legacy.identity,
            bob_bundle_for_alice_legacy,
        )
        .unwrap();

        let alice_bob = proteus_wasm::session::Session::deserialise(
            &alice.identity,
            &alice_legacy_bob.serialise().unwrap(),
        )
        .unwrap();

        assert_eq!(
            alice_legacy_bob.serialise().unwrap(),
            alice_bob.serialise().unwrap(),
        );
    }

    #[test]
    fn serialize_interop_envelope() {
        let (alice, mut alice_legacy) = get_client_pair();

        // Start a session with `bob` from both `alice` and `alice_legacy` and check if `Sessions` are also compatible
        let mut bob_legacy = LegacyClient::new();
        let bob_bundle_for_alice_legacy = bob_legacy.new_prekey();

        alice_legacy.init_session_from_prekey_bundle(
            "ab",
            &bob_bundle_for_alice_legacy.serialise().unwrap(),
        );

        let alice_legacy_bob = alice_legacy.session("ab");

        let mut alice_bob = proteus_wasm::session::Session::deserialise(
            &alice.identity,
            &alice_legacy_bob.serialise().unwrap(),
        )
        .unwrap();

        let alice_msg = alice_bob.encrypt(MSG).unwrap();
        let alice_legacy_msg = alice_legacy_bob.encrypt(MSG).unwrap();

        assert_eq!(
            alice_legacy_msg.serialise().unwrap(),
            alice_msg.serialise().unwrap(),
        );
    }
}

mod communication {
    use super::*;
    use pretty_assertions::assert_eq;

    #[async_std::test]
    async fn proteus_v2_interop() {
        assert!(proteus_wasm::init());
        assert!(proteus::init());

        let mut alice = Client::new();
        let mut bob = Client::new();
        let bob_bundle = bob.new_prekey();

        alice.init_session_from_prekey_bundle("ab", &bob_bundle.serialise().unwrap());

        let hello_bob_from_alice = alice.encrypt("ab", MSG);
        let hello_bob = bob.decrypt("ba", &hello_bob_from_alice).await;
        assert_eq!(hello_bob, MSG);

        let hello_alice_from_bob = bob.encrypt("ba", MSG);
        let decrypted = alice.decrypt("ab", &hello_alice_from_bob).await;
        assert_eq!(decrypted, MSG);
    }

    #[async_std::test]
    async fn proteus_v1_interop() {
        assert!(proteus_wasm::init());
        assert!(proteus::init());

        let mut alice = LegacyClient::new();
        let mut bob = LegacyClient::new();
        let bob_bundle = bob.new_prekey();

        alice.init_session_from_prekey_bundle("ab", &bob_bundle.serialise().unwrap());

        let hello_bob_from_alice = alice.encrypt("ab", MSG);
        let hello_bob = bob.decrypt("ba", &hello_bob_from_alice);
        assert_eq!(hello_bob, MSG);

        let hello_alice_from_bob = &bob.encrypt("ba", MSG);
        let decrypted = alice.decrypt("ab", &hello_alice_from_bob);
        assert_eq!(decrypted, MSG);
    }

    #[async_std::test]
    async fn proteus_v2_to_v1_interop() {
        assert!(proteus_wasm::init());
        assert!(proteus::init());

        let mut alice = Client::new();
        let mut bob = LegacyClient::new();
        let bob_bundle = bob.new_prekey();

        alice.init_session_from_prekey_bundle("ab", &bob_bundle.serialise().unwrap());

        let hello_bob_from_alice = alice.encrypt("ab", MSG);
        let hello_bob = bob.decrypt("ba", &hello_bob_from_alice);
        assert_eq!(hello_bob, MSG);

        let hello_alice_from_bob = bob.encrypt("ba", MSG);
        let decrypted = alice.decrypt("ab", &hello_alice_from_bob).await;
        assert_eq!(decrypted, MSG);
    }

    #[async_std::test]
    async fn proteus_v1_to_v2_interop() {
        assert!(proteus_wasm::init());
        assert!(proteus::init());

        let mut alice = LegacyClient::new();
        let mut bob = Client::new();
        let bob_bundle = bob.new_prekey();

        alice.init_session_from_prekey_bundle("ab", &bob_bundle.serialise().unwrap());

        let hello_bob_from_alice = alice.encrypt("ab", MSG);
        let hello_bob = bob.decrypt("ba", &hello_bob_from_alice).await;
        assert_eq!(hello_bob, MSG);

        let hello_alice_from_bob = bob.encrypt("ba", MSG);
        let decrypted = alice.decrypt("ab", &hello_alice_from_bob);
        assert_eq!(decrypted, MSG);
    }
}

mod cryptobox_interop {
    use super::*;
    use pretty_assertions::assert_eq;

    #[async_std::test]
    async fn post_import_communication_scenario() {
        let mut alice_legacy = LegacyClient::new();
        let mut bob_legacy = LegacyClient::new();
        let mut charlie_new = Client::new();

        let bob_pkb = bob_legacy.new_prekey();
        let charlie_pkb = charlie_new.new_prekey();

        alice_legacy.init_session_from_prekey_bundle("ab", &bob_pkb.serialise().unwrap());
        alice_legacy.init_session_from_prekey_bundle("ac", &charlie_pkb.serialise().unwrap());

        // alice -> bob
        let alice_bob_handshake = alice_legacy.encrypt("ab", MSG);
        let bob_msg = bob_legacy.decrypt("ba", &alice_bob_handshake);
        assert_eq!(bob_msg, MSG);
        // bob -> alice
        let bob_alice_msg = bob_legacy.encrypt("ba", MSG);
        let alice_msg = alice_legacy.decrypt("ab", &bob_alice_msg);
        assert_eq!(alice_msg, MSG);

        // alice -> charlie
        let alice_charlie_handshake = alice_legacy.encrypt("ac", MSG);
        let charlie_msg = charlie_new.decrypt("ca", &alice_charlie_handshake).await;
        assert_eq!(charlie_msg, MSG);
        // charlie -> alice
        let charlie_alice_msg = charlie_new.encrypt("ca", MSG);
        let alice_msg = alice_legacy.decrypt("ac", &charlie_alice_msg);
        assert_eq!(alice_msg, MSG);

        // Upgrade alice to proteus 2.0
        let mut alice_new = alice_legacy.upgrade();

        // alice -> bob
        let alice_bob_handshake = alice_new.encrypt("ab", MSG);
        let bob_msg = bob_legacy.decrypt("ba", &alice_bob_handshake);
        assert_eq!(bob_msg, MSG);
        // bob -> alice
        let bob_alice_msg = bob_legacy.encrypt("ba", MSG);
        let alice_msg = alice_new.decrypt("ab", &bob_alice_msg).await;
        assert_eq!(alice_msg, MSG);

        // alice -> charlie
        let alice_charlie_handshake = alice_new.encrypt("ac", MSG);
        let charlie_msg = charlie_new.decrypt("ca", &alice_charlie_handshake).await;
        assert_eq!(charlie_msg, MSG);
        // charlie -> alice
        let charlie_alice_msg = charlie_new.encrypt("ca", MSG);
        let alice_msg = alice_new.decrypt("ac", &charlie_alice_msg).await;
        assert_eq!(alice_msg, MSG);

        // For fun, downgrade alice back again to proteus 1.0
        let mut alice_legacy = alice_new.downgrade();

        // alice -> bob
        let alice_bob_handshake = alice_legacy.encrypt("ab", MSG);
        let bob_msg = bob_legacy.decrypt("ba", &alice_bob_handshake);
        assert_eq!(bob_msg, MSG);
        // bob -> alice
        let bob_alice_msg = bob_legacy.encrypt("ba", MSG);
        let alice_msg = alice_legacy.decrypt("ab", &bob_alice_msg);
        assert_eq!(alice_msg, MSG);

        // alice -> charlie
        let alice_charlie_handshake = alice_legacy.encrypt("ac", MSG);
        let charlie_msg = charlie_new.decrypt("ca", &alice_charlie_handshake).await;
        assert_eq!(charlie_msg, MSG);
        // charlie -> alice
        let charlie_alice_msg = charlie_new.encrypt("ca", MSG);
        let alice_msg = alice_legacy.decrypt("ac", &charlie_alice_msg);
        assert_eq!(alice_msg, MSG);
    }
}
