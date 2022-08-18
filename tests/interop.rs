use pretty_assertions::assert_eq;
use wasm_bindgen_test::*;

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

macro_rules! impl_harness_for_crate {
    ($store:ident, $client:ident, $target:ident) => {
        impl $target::session::PreKeyStore for $store<$target::keys::PreKey> {
            type Error = ();

            fn prekey(
                &mut self,
                id: $target::keys::PreKeyId,
            ) -> Result<Option<$target::keys::PreKey>, ()> {
                Ok(self.prekeys.iter().find(|k| k.key_id == id).cloned())
            }

            fn remove(&mut self, id: $target::keys::PreKeyId) -> Result<(), ()> {
                self.prekeys
                    .iter()
                    .position(|k| k.key_id == id)
                    .map(|idx| self.prekeys.swap_remove(idx));

                Ok(())
            }
        }

        pub struct $client {
            pub identity: $target::keys::IdentityKeyPair,
            pub store: TestStore<$target::keys::PreKey>,
        }

        impl $client {
            pub fn new() -> Self {
                let mut client = Self {
                    identity: $target::keys::IdentityKeyPair::new(),
                    store: TestStore::default(),
                };

                client.gen_prekeys(10);

                client
            }

            pub fn from_raw_sk(sk: [u8; 32]) -> Self {
                let mut client = Self {
                    identity: $target::keys::IdentityKeyPair::from_raw_sk(sk),
                    store: TestStore::default(),
                };

                client.gen_prekeys(10);

                client
            }

            pub fn gen_prekeys(&mut self, count: u16) {
                let id = self
                    .store
                    .prekeys
                    .first()
                    .map(|pk| pk.key_id)
                    .unwrap_or_else(|| $target::keys::PreKeyId::new(0));

                dbg!(id);

                let new_prekeys = $target::keys::gen_prekeys(id, count);
                for pk in new_prekeys.into_iter() {
                    self.store.prekeys.push(pk);
                }
            }

            pub fn get_prekey_bundle(&self, id: u16) -> Option<$target::keys::PreKeyBundle> {
                if id == 0 {
                    panic!("PreKeyId cannot be 0. Ever.");
                }

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

#[test]
#[wasm_bindgen_test]
fn serialize_interop() {
    let alice = Client::new();
    let raw_sk = alice.identity.secret_key.to_bytes();
    let alice_legacy = LegacyClient::new();
    // TODO: Add test utils to proteus-legacy so that we can inspect stuff
    // alice_legacy.identity.secret_key

    // let b = alice.identity.secret_key.0.to_bytes();
    // let alice_legacy = LegacyClient::new();
    // let alice_bundle = alice.get_prekey_bundle(1).unwrap();
    // let alice_legacy_bundle = alice_legacy.get_prekey_bundle(1).unwrap();

    // assert_eq!(
    //     alice_bundle.serialise().unwrap(),
    //     alice_legacy_bundle.serialise().unwrap()
    // );
}

const MSG: &[u8] = b"Hello world!";

macro_rules! impl_interop_test {
    ($test_name:ident, $client1:ident @ $client1_crate:ident, $client2:ident @ $client2_crate:ident) => {
        #[test]
        #[wasm_bindgen_test]
        fn $test_name() {
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
