extern crate proteus;
use proteus::{keys::*, session::*};

#[derive(Debug)]
struct TestStore {
    prekeys: Vec<PreKey>,
}

impl PreKeyStore for TestStore {
    type Error = ();

    fn prekey(&mut self, id: PreKeyId) -> Result<Option<PreKey>, ()> {
        Ok(self
            .prekeys
            .iter()
            .find(|k| k.key_id == id)
            .map(|k| k.clone()))
    }

    fn remove(&mut self, id: PreKeyId) -> Result<(), ()> {
        self.prekeys
            .iter()
            .position(|k| k.key_id == id)
            .map(|ix| self.prekeys.swap_remove(ix));
        Ok(())
    }
}

fn setup() -> (
    TestStore,
    IdentityKeyPair,
    PreKeyBundle,
    TestStore,
    IdentityKeyPair,
    PreKeyBundle,
) {
    let alice_ident = IdentityKeyPair::new();
    let bob_ident = IdentityKeyPair::new();

    let mut bob_store = TestStore {
        prekeys: vec![PreKey::new(PreKeyId::new(1))],
    };
    let mut alice_store = TestStore {
        prekeys: vec![PreKey::new(PreKeyId::new(1))],
    };

    // Create key bundles for both.
    let bob_prekey = bob_store.prekey(PreKeyId::new(1)).unwrap().unwrap();
    let bob_bundle = PreKeyBundle::new(bob_ident.public_key.clone(), &bob_prekey);
    let alice_prekey = alice_store.prekey(PreKeyId::new(1)).unwrap().unwrap();
    let alice_bundle = PreKeyBundle::new(alice_ident.public_key.clone(), &alice_prekey);

    (
        bob_store,
        bob_ident,
        bob_bundle,
        alice_store,
        alice_ident,
        alice_bundle,
    )
}

#[test]
fn test_clone_bob_alice_init() {
    let (mut bob_store, bob_ident, bob_bundle, mut alice_store, alice_ident, _alice_bundle) =
        setup();
    // Alice initiates the session.
    let mut alice = Session::init_from_prekey::<()>(&alice_ident, bob_bundle).unwrap();
    let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();

    // Bob inits from Alice' message.
    let mut bob = match Session::init_from_message(&bob_ident, &mut bob_store, &hello_bob) {
        Ok((s, b)) => {
            assert_eq!(b"Hello Bob!"[..], b[..]);
            s
        }
        Err(e) => {
            println!("Error: {:?}", e);
            unreachable!()
        }
    };

    // Bob responds to Alice.
    let hello_alice = bob.encrypt(b"Hello Alice!").unwrap().into_owned();
    let hello_alice = alice.decrypt(&mut alice_store, &hello_alice).unwrap();
    assert_eq!(hello_alice, b"Hello Alice!");

    // === Clone Bob ===
    let mut bob_clone = bob.clone();
    let mut alice_messages = Vec::new();
    println!("Bob:\n{:?}", bob);

    let msg1 = b"Alice message";
    let msg2 = b"Bob message";

    // Exchange 5 messages between bob and alice both directions.
    println!("start sending 5 messages both directions");
    for _ in 0..5 {
        println!("Alice -> Bob");
        let a2b = alice.encrypt(msg1).unwrap().into_owned();
        alice_messages.push(a2b.clone());
        let a2b_msg = bob.decrypt(&mut bob_store, &a2b).unwrap();
        assert_eq!(&msg1[..], &a2b_msg[..]);

        println!("Bob -> Alice");
        let b2a = bob.encrypt(msg2).unwrap().into_owned();
        let b2a_msg = alice.decrypt(&mut alice_store, &b2a).unwrap();
        assert_eq!(&msg2[..], &b2a_msg[..]);
    }

    // Check what bob_clone can decrypt.
    for (i, bm) in alice_messages.iter().enumerate() {
        println!("Bob Clone Decrypt {:?}", i);
        if i == 0 {
            // We can successfully decrypt the first message.
            let a2b_msg = bob_clone
                .decrypt(&mut bob_store /* this is not used here */, &bm)
                .unwrap();
            assert_eq!(&msg1[..], &a2b_msg[..]);
        } else {
            // After the first message it fails.
            assert_eq!(
                Err(Error::InvalidSignature),
                bob_clone.decrypt(&mut bob_store /* this is not used here */, &bm)
            );
        }
    }
    // Check if bob_clone can communicate with alice.
    println!("Bob -> Alice");
    let b2a = bob_clone.encrypt(msg2).unwrap().into_owned();
    assert_eq!(
        Err(Error::InvalidSignature),
        alice.decrypt(&mut alice_store, &b2a)
    );

    println!("Alice -> Bob");
    let a2b = alice.encrypt(msg1).unwrap().into_owned();
    alice_messages.push(a2b.clone());
    assert_eq!(
        Err(Error::InvalidSignature),
        bob_clone.decrypt(&mut bob_store, &a2b)
    );
}

#[test]
fn test_clone_bob_bob_init() {
    let (mut bob_store, bob_ident, _bob_bundle, mut alice_store, alice_ident, alice_bundle) =
        setup();

    // Bob initiates the session.
    let mut bob = Session::init_from_prekey::<()>(&bob_ident, alice_bundle).unwrap();
    let hello_alice = bob.encrypt(b"Hello Alice!").unwrap().into_owned();

    // Alice inits from Bob's message.
    let mut alice = match Session::init_from_message(&alice_ident, &mut alice_store, &hello_alice) {
        Ok((s, b)) => {
            assert_eq!(b"Hello Alice!"[..], b[..]);
            s
        }
        Err(e) => {
            println!("Error: {:?}", e);
            unreachable!()
        }
    };

    // Alice responds to Bob.
    let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();
    let hello_bob = bob.decrypt(&mut bob_store, &hello_bob).unwrap();
    assert_eq!(hello_bob, b"Hello Bob!");

    // === Clone Bob ===
    let mut bob_clone = bob.clone();
    let mut alice_messages = Vec::new();
    println!("Bob:\n{:?}", bob);

    let msg1 = b"Alice message";
    let msg2 = b"Bob message";

    // Exchange 5 messages between bob and alice both directions.
    println!("start sending 5 messages both directions");
    for _ in 0..5 {
        println!("Alice -> Bob");
        let a2b = alice.encrypt(msg1).unwrap().into_owned();
        alice_messages.push(a2b.clone());
        let a2b_msg = bob.decrypt(&mut bob_store, &a2b).unwrap();
        assert_eq!(&msg1[..], &a2b_msg[..]);

        println!("Bob -> Alice");
        let b2a = bob.encrypt(msg2).unwrap().into_owned();
        let b2a_msg = alice.decrypt(&mut alice_store, &b2a).unwrap();
        assert_eq!(&msg2[..], &b2a_msg[..]);
    }

    // Check what bob_clone can decrypt.
    for (i, bm) in alice_messages.iter().enumerate() {
        println!("Bob Clone Decrypt {:?}", i);
        if i == 0 || i == 1 {
            // We can successfully decrypt the first two messages.
            let a2b_msg = bob_clone
                .decrypt(&mut bob_store /* this is not used here */, &bm)
                .unwrap();
            assert_eq!(&msg1[..], &a2b_msg[..]);
        } else {
            // After the first two messages it fails.
            assert_eq!(
                Err(Error::InvalidSignature),
                bob_clone.decrypt(&mut bob_store /* this is not used here */, &bm)
            );
        }
    }

    // Check if bob_clone can communicate with alice.
    println!("Bob -> Alice");
    let b2a = bob_clone.encrypt(msg2).unwrap().into_owned();
    assert_eq!(
        Err(Error::InvalidSignature),
        alice.decrypt(&mut alice_store, &b2a)
    );

    println!("Alice -> Bob");
    let a2b = alice.encrypt(msg1).unwrap().into_owned();
    alice_messages.push(a2b.clone());
    assert_eq!(
        Err(Error::InvalidSignature),
        bob_clone.decrypt(&mut bob_store, &a2b)
    );
}

#[test]
fn test_clone_bob_bob_init2() {
    let (mut bob_store, bob_ident, _bob_bundle, mut alice_store, alice_ident, alice_bundle) =
        setup();

    // Bob initiates the session.
    let mut bob = Session::init_from_prekey::<()>(&bob_ident, alice_bundle).unwrap();
    let hello_alice = bob.encrypt(b"Hello Alice!").unwrap().into_owned();

    // Alice inits from Bob's message.
    let mut alice = match Session::init_from_message(&alice_ident, &mut alice_store, &hello_alice) {
        Ok((s, b)) => {
            assert_eq!(b"Hello Alice!"[..], b[..]);
            s
        }
        Err(e) => {
            println!("Error: {:?}", e);
            unreachable!()
        }
    };

    // Alice responds to Bob.
    let hello_bob = alice.encrypt(b"Hello Bob!").unwrap().into_owned();
    let hello_bob = bob.decrypt(&mut bob_store, &hello_bob).unwrap();
    assert_eq!(hello_bob, b"Hello Bob!");

    // === Clone Bob ===
    let mut bob_clone = bob.clone();
    let mut alice_messages = Vec::new();
    println!("Bob:\n{:?}", bob);

    let msg1 = b"Alice message";
    let msg2 = b"Bob message";

    // Exchange 5 messages between bob and alice both directions.
    println!("start sending 5 messages both directions");
    for _ in 0..5 {
        println!("Bob -> Alice");
        let b2a = bob.encrypt(msg2).unwrap().into_owned();
        let b2a_msg = alice.decrypt(&mut alice_store, &b2a).unwrap();
        assert_eq!(&msg2[..], &b2a_msg[..]);
        println!("Alice -> Bob");
        let a2b = alice.encrypt(msg1).unwrap().into_owned();
        alice_messages.push(a2b.clone());
        let a2b_msg = bob.decrypt(&mut bob_store, &a2b).unwrap();
        assert_eq!(&msg1[..], &a2b_msg[..]);
    }

    // Check what bob_clone can decrypt.
    for (i, bm) in alice_messages.iter().enumerate() {
        println!("Bob Clone Decrypt {:?}", i);
        if i == 0 {
            // We can successfully decrypt the first message.
            let a2b_msg = bob_clone
                .decrypt(&mut bob_store /* this is not used here */, &bm)
                .unwrap();
            assert_eq!(&msg1[..], &a2b_msg[..]);
        } else {
            // After the first message it fails.
            assert_eq!(
                Err(Error::InvalidSignature),
                bob_clone.decrypt(&mut bob_store /* this is not used here */, &bm)
            );
        }
    }

    // Check if bob_clone can communicate with alice.
    println!("Bob -> Alice");
    let b2a = bob_clone.encrypt(msg2).unwrap().into_owned();
    assert_eq!(
        Err(Error::InvalidSignature),
        alice.decrypt(&mut alice_store, &b2a)
    );

    println!("Alice -> Bob");
    let a2b = alice.encrypt(msg1).unwrap().into_owned();
    alice_messages.push(a2b.clone());
    assert_eq!(
        Err(Error::InvalidSignature),
        bob_clone.decrypt(&mut bob_store, &a2b)
    );
}
