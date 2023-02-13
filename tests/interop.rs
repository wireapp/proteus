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

#![cfg(all(test, not(target_family = "wasm")))]

mod common;
use common::*;

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
            &alice.identity.secret_key.to_keypair_bytes(),
        );

        assert_eq!(
            identity_new_into_legacy.public_key.public_key.as_slice(),
            alice.identity.public_key.public_key.as_slice(),
        );

        assert_eq!(
            &identity_legacy_into_new.secret_key.to_keypair_bytes(),
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
