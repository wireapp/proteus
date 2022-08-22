
const ALICE_EXTENDED_SK: [u8; 64] = [
    8, 130, 70, 168, 110, 135, 69, 114, 48, 89, 69, 6, 149, 219, 54, 242, 47, 58, 47, 56, 92, 80,
    28, 99, 39, 174, 163, 50, 136, 222, 73, 91, 202, 21, 122, 0, 1, 7, 239, 209, 227, 4, 51, 91,
    23, 22, 23, 59, 35, 215, 100, 94, 135, 63, 175, 124, 44, 229, 49, 232, 93, 173, 156, 181,
];

fn alice_extended_sk_to_sk() -> [u8; 32] {
    let mut ret = [0; 32];
    ret.copy_from_slice(&ALICE_EXTENDED_SK[..32]);
    ret
}

#[test]
#[wasm_bindgen_test]
fn serialize_interop() {
    assert!(proteus::init());
    assert!(proteus_legacy::init());
    let alice = Client::from_raw_sk(alice_extended_sk_to_sk());
    let mut alice_legacy = LegacyClient::from_raw_sk(ALICE_EXTENDED_SK);

    let alice_prekeys = alice.store.prekeys.iter().map(|pk| pk.serialise().unwrap());

    for pk in alice_prekeys {
        alice_legacy
            .store
            .prekeys
            .push(proteus_legacy::keys::PreKey::deserialise(&pk).unwrap());
    }

    let alice_bundle = alice.get_prekey_bundle(1).unwrap();
    let alice_legacy_bundle = alice_legacy.get_prekey_bundle(1).unwrap();

    assert_eq!(
        alice_bundle.serialise().unwrap(),
        alice_legacy_bundle.serialise().unwrap()
    );
}
