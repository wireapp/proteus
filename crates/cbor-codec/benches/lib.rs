// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

// extern crate cbor;
// extern crate quickcheck;
// extern crate rand;
// extern crate test;

// use cbor::random::gen_value;
// use cbor::{Config, GenericDecoder, GenericEncoder};
// use quickcheck::StdGen;
// use rand::chacha::ChaChaRng;
// use std::io::Cursor;
// use test::Bencher;

// fn mk_value(min: usize) -> Vec<u8> {
//     let mut g = StdGen::new(ChaChaRng::new_unseeded(), 255);
//     let mut e = GenericEncoder::new(Cursor::new(Vec::new()));
//     e.borrow_mut().array(min).unwrap();
//     for _ in 0..min {
//         e.value(&gen_value(3, &mut g)).unwrap()
//     }
//     e.into_inner().into_writer().into_inner()
// }

// #[bench]
// fn random_value_roundtrip(b: &mut Bencher) {
//     let mut w = Cursor::new(mk_value(30));
//     b.iter(|| {
//         assert!(GenericDecoder::new(Config::default(), &mut w)
//             .value()
//             .ok()
//             .is_some());
//         w.set_position(0);
//     });
// }
