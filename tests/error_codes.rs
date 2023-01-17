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
#![cfg(test)]

mod common;
use common::*;
use proteus_wasm::{
    error::ProteusError,
    keys::{IdentityKeyPair, PublicKey},
};
use wasm_bindgen_test::wasm_bindgen_test;

use proteus_traits::{ProteusErrorCode as _, ProteusErrorKind};

#[async_std::test]
#[wasm_bindgen_test]
async fn error_code_100() {
    let k = IdentityKeyPair::new();
    let bytes: Vec<u8> = k
        .public_key
        .public_key
        .as_slice()
        .iter()
        .map(|_| 0)
        .collect();

    let pk = PublicKey::from_bytes(bytes).unwrap();

    let Err(e) = k.secret_key.shared_secret(&pk) else {
        unreachable!("Not a zero pk");
    };

    assert_eq!(e, ProteusError::Zero);

    let error_code = e.code();
    assert_eq!(error_code, ProteusErrorKind::AssertZeroArray);
    assert_eq!(ProteusErrorKind::AssertZeroArray as u16, 100);
    assert_eq!(error_code as u16, ProteusErrorKind::AssertZeroArray as u16);
    assert_eq!(error_code as u16, 100);
}

#[async_std::test]
#[wasm_bindgen_test]
async fn error_code_101() {
    let mut alice = Client::new();
    let mut bob = Client::new();

    let bob_pk = bob.new_prekey();
    alice.init_session_from_prekey_bundle("ab", &bob_pk.serialise().unwrap());

    let ab_msg = alice.encrypt("ab", MSG);

    assert_eq!(
        bob.init_session_from_message("ba", &ab_msg).await.unwrap(),
        MSG
    );

    let Err(e) = bob.init_session_from_message("ba", &ab_msg).await else {
        panic!("Bob decrypted the same message twice successfully. There's a bug there");
    };

    let error_code = e.code();
    assert_eq!(error_code, ProteusErrorKind::PreKeyNotFound);
    assert_eq!(ProteusErrorKind::PreKeyNotFound as u16, 101);
    assert_eq!(error_code as u16, ProteusErrorKind::PreKeyNotFound as u16);
    assert_eq!(error_code as u16, 101);
}

#[async_std::test]
#[wasm_bindgen_test]
async fn error_code_102() {
    let mut alice = Client::new();
    let mut bob = Client::new();

    let bob_pk = bob.new_prekey();
    alice.init_session_from_prekey_bundle("ab", &bob_pk.serialise().unwrap());

    let ab_msg = alice.encrypt("ab", MSG);
    assert_eq!(bob.decrypt("ba", &ab_msg).await, MSG);
    let alice_bob_session = alice.session("ab");

    // Corrupt the session tag to trigger error 102
    **alice_bob_session.session_tag_mut() = [0u8; 16];

    let Err(e) = alice_bob_session.encrypt(b"This should trigger error 102") else {
        panic!("Corrupted session tag didn't trigger error code 102");
    };

    let error_code = e.code();
    assert_eq!(error_code, ProteusErrorKind::SessionStateNotFoundForTag);
    assert_eq!(ProteusErrorKind::SessionStateNotFoundForTag as u16, 102);
    assert_eq!(
        error_code as u16,
        ProteusErrorKind::SessionStateNotFoundForTag as u16
    );
    assert_eq!(error_code as u16, 102);
}

#[async_std::test]
#[wasm_bindgen_test]
#[ignore = "unimplemented - no idea how to trigger this"]
async fn error_code_103() {}

#[async_std::test]
#[wasm_bindgen_test]
#[ignore = "unimplemented - no idea how to trigger this"]
async fn error_code_104() {}
