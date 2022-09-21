#![cfg(all(test, not(target_family = "wasm")))]

use pretty_assertions::{assert_eq, assert_ne, assert_str_eq};

#[derive(Debug)]
pub struct TestStore<T> {
    pub prekeys: Vec<T>,
}

impl<T> Default for TestStore<T> {
    fn default() -> Self {
        Self {
            prekeys: Vec::new(),
        }
    }
}

impl proteus_legacy::session::PreKeyStore for TestStore<proteus_legacy::keys::PreKey> {
    type Error = ();

    fn prekey(
        &mut self,
        id: proteus_legacy::keys::PreKeyId,
    ) -> Result<Option<proteus_legacy::keys::PreKey>, ()> {
        Ok(self.prekeys.iter().find(|k| k.key_id == id).cloned())
    }

    fn remove(&mut self, id: proteus_legacy::keys::PreKeyId) -> Result<(), ()> {
        self.prekeys
            .iter()
            .position(|k| k.key_id == id)
            .map(|idx| self.prekeys.swap_remove(idx));

        Ok(())
    }
}

impl proteus_traits::PreKeyStore for TestStore<proteus::keys::PreKey> {
    type Error = ();

    fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, ()> {
        Ok(self
            .prekeys
            .iter()
            .find(|k| k.key_id.value() == id)
            .map(|pk| proteus::keys::PreKey::serialise(pk).unwrap()))
    }

    fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), ()> {
        self.prekeys
            .iter()
            .position(|k| k.key_id.value() == id)
            .map(|idx| self.prekeys.swap_remove(idx));

        Ok(())
    }
}

macro_rules! impl_harness_for_crate {
    ($store:ident, $client:ident, $target:ident) => {
        pub struct $client {
            pub identity: $target::keys::IdentityKeyPair,
            pub store: TestStore<$target::keys::PreKey>,
        }

        impl Default for $client {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $client {
            #[must_use]
            pub fn new() -> Self {
                let mut client = Self {
                    identity: $target::keys::IdentityKeyPair::new(),
                    store: TestStore::default(),
                };

                client.gen_prekeys(10);

                client
            }

            #[must_use]
            pub fn from_raw_sk(sk: [u8; 64]) -> Self {
                let client = Self {
                    identity: $target::keys::IdentityKeyPair::from_raw_secret_key(sk),
                    store: TestStore::default(),
                };

                client
            }

            pub fn gen_prekeys(&mut self, count: u16) {
                let id = self
                    .store
                    .prekeys
                    .first()
                    .map(|pk| pk.key_id)
                    .unwrap_or_else(|| $target::keys::PreKeyId::new(0));

                let new_prekeys = $target::keys::gen_prekeys(id, count);
                for pk in new_prekeys.into_iter() {
                    self.store.prekeys.push(pk);
                }
            }

            #[must_use]
            pub fn get_prekey_bundle(&self, id: u16) -> Option<$target::keys::PreKeyBundle> {
                assert_ne!(id, 0, "PreKeyId cannot be 0. Ever.");

                self.store
                    .prekeys
                    .iter()
                    .find(|pk| pk.key_id.value() == id)
                    .map(|pk| {
                        $target::keys::PreKeyBundle::new(self.identity.public_key.clone(), &pk)
                    })
            }
        }
    };
}

impl_harness_for_crate!(TestStore, Client, proteus);
impl_harness_for_crate!(TestStore, LegacyClient, proteus_legacy);

impl Client {
    pub fn from_raw(sk: [u8; 64], pk: [u8; 32]) -> Self {
        Client {
            identity: unsafe { proteus::keys::IdentityKeyPair::from_raw_key_pair(sk, pk) },
            store: TestStore::default(),
        }
    }
}

const MSG: &[u8] = b"Hello world!";

macro_rules! impl_interop_test {
    ($test_name:ident, $client1:ident @ $client1_crate:ident, $client2:ident @ $client2_crate:ident) => {
        #[test]
        fn $test_name() {
            assert!(proteus::init());
            assert!(proteus_legacy::init());
            let mut alice = $client1::new();
            let mut bob = $client2::new();
            let bob_bundle = bob.get_prekey_bundle(1).unwrap();
            let bob_bundle_for_alice =
                $client1_crate::keys::PreKeyBundle::deserialise(&bob_bundle.serialise().unwrap())
                    .unwrap();

            let mut alice_bob = $client1_crate::session::Session::init_from_prekey::<()>(
                &alice.identity,
                bob_bundle_for_alice,
            )
            .unwrap();

            let hello_bob_from_alice = $client2_crate::message::Envelope::deserialise(
                &alice_bob.encrypt(MSG).unwrap().serialise().unwrap(),
            )
            .unwrap();

            let (mut bob_alice, hello_bob) = $client2_crate::session::Session::init_from_message(
                &bob.identity,
                &mut bob.store,
                &hello_bob_from_alice,
            )
            .unwrap();

            assert_eq!(hello_bob, MSG);

            let hello_alice_from_bob = $client1_crate::message::Envelope::deserialise(
                &bob_alice.encrypt(MSG).unwrap().serialise().unwrap(),
            )
            .unwrap();

            assert_eq!(
                alice_bob
                    .decrypt(&mut alice.store, &hello_alice_from_bob)
                    .unwrap(),
                MSG
            );
        }
    };
}

impl_interop_test!(proteus_v2_interop, Client @ proteus, Client @ proteus);
impl_interop_test!(proteus_v1_interop, LegacyClient @ proteus_legacy, LegacyClient @ proteus_legacy);
impl_interop_test!(proteus_v2_to_v1_interop, Client @ proteus, LegacyClient @ proteus_legacy);
impl_interop_test!(proteus_v1_to_v2_interop, LegacyClient @ proteus_legacy, Client @ proteus);

fn get_client_pair() -> (Client, LegacyClient) {
    assert!(proteus::init());
    assert!(proteus_legacy::init());
    let alice_legacy = LegacyClient::new();
    let mut alice = Client::from_raw(
        alice_legacy.identity.secret_key.to_bytes(),
        alice_legacy.identity.public_key.public_key.to_bytes(),
    );
    // let mut alice = Client::from_raw_sk(alice_legacy.identity.secret_key.to_bytes());

    let alice_legacy_prekeys = alice_legacy
        .store
        .prekeys
        .iter()
        .map(|pk| pk.serialise().unwrap());

    for pk in alice_legacy_prekeys {
        alice
            .store
            .prekeys
            .push(proteus::keys::PreKey::deserialise(&pk).unwrap());
    }

    (alice, alice_legacy)
}

#[test]
fn serialize_interop_identity() {
    let (alice, alice_legacy) = get_client_pair();
    let identity_legacy_ser = alice_legacy.identity.serialise().unwrap();
    let identity_ser = alice.identity.serialise().unwrap();

    let identity_legacy: ciborium::value::Value =
        ciborium::de::from_reader(&identity_legacy_ser[..]).unwrap();

    let identity: ciborium::value::Value = ciborium::de::from_reader(&identity_ser[..]).unwrap();

    assert_eq!(identity_legacy, identity);

    assert_str_eq!(hex::encode(identity_legacy_ser), hex::encode(identity_ser),);
}

#[test]
fn serialize_interop_prekey() {
    let (alice, alice_legacy) = get_client_pair();

    let prekey = alice.store.prekeys.get(0).unwrap();
    let prekey_legacy = alice_legacy.store.prekeys.get(0).unwrap();

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
    let alice_bundle = alice.get_prekey_bundle(1).unwrap();
    let alice_legacy_bundle = alice_legacy.get_prekey_bundle(1).unwrap();

    assert_eq!(
        alice_legacy_bundle.serialise().unwrap(),
        alice_bundle.serialise().unwrap(),
    );
}

#[test]
fn serialize_interop_session() {
    let (alice, alice_legacy) = get_client_pair();

    // Start a session with `bob` from both `alice` and `alice_legacy` and check if `Sessions` are also compatible
    let bob_legacy = LegacyClient::new();
    let bob_bundle_for_alice_legacy = bob_legacy.get_prekey_bundle(1).unwrap();

    let alice_legacy_bob = proteus_legacy::session::Session::init_from_prekey::<()>(
        &alice_legacy.identity,
        bob_bundle_for_alice_legacy,
    )
    .unwrap();

    let alice_bob = proteus::session::Session::deserialise(
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
    let (alice, alice_legacy) = get_client_pair();

    // Start a session with `bob` from both `alice` and `alice_legacy` and check if `Sessions` are also compatible
    let bob_legacy = LegacyClient::new();
    let bob_bundle_for_alice_legacy = bob_legacy.get_prekey_bundle(1).unwrap();

    let mut alice_legacy_bob = proteus_legacy::session::Session::init_from_prekey::<()>(
        &alice_legacy.identity,
        bob_bundle_for_alice_legacy,
    )
    .unwrap();

    let mut alice_bob = proteus::session::Session::deserialise(
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
