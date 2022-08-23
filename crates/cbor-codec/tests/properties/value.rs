// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::random::gen_value;
use cbor::value::{Key, Value};
use cbor::{GenericDecoder, GenericEncoder};
use quickcheck::{Arbitrary, Gen, QuickCheck, StdGen};
use rand;
use std::collections::BTreeMap;
use util::{as_i64, as_u64, identity};

#[derive(Clone, Debug)]
pub struct ArbitraryValue(pub Value);

impl Arbitrary for ArbitraryValue {
    fn arbitrary<G: Gen>(g: &mut G) -> ArbitraryValue {
        ArbitraryValue(gen_value(3, g))
    }
}

#[test]
fn identity_value() {
    fn prop(a: ArbitraryValue) -> bool {
        identity(
            |e| GenericEncoder::from_encoder(e).value(&a.0),
            |d| {
                let y = GenericDecoder::from_decoder(d).value().unwrap();
                if eq(&a.0, &y) {
                    true
                } else {
                    println!("input = {:?}\n\noutput = {:?}", a.0, y);
                    false
                }
            },
        )
    }
    QuickCheck::new()
        .tests(200)
        .gen(StdGen::new(rand::thread_rng(), 255))
        .quickcheck(prop as fn(ArbitraryValue) -> bool)
}

pub fn eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (&Value::Array(ref x), &Value::Array(ref y)) => {
            x.iter().zip(y.iter()).all(|(vx, vy)| eq(vx, vy))
        }
        (&Value::Bool(x), &Value::Bool(y)) => x == y,
        (&Value::Bytes(ref x), &Value::Bytes(ref y)) => x == y,
        (&Value::Text(ref x), &Value::Text(ref y)) => x == y,
        (&Value::Simple(x), &Value::Simple(y)) => x == y,
        (&Value::Null, &Value::Null) => true,
        (&Value::Undefined, &Value::Undefined) => true,
        (&Value::F32(x), &Value::F32(y)) => x.is_nan() && y.is_nan() || x == y,
        (&Value::F64(x), &Value::F64(y)) => x.is_nan() && y.is_nan() || x == y,
        (&Value::Map(ref x), &Value::Map(ref y)) => eq_map(x, y),
        (&Value::Tagged(ta, ref x), &Value::Tagged(tb, ref y)) => ta == tb && eq(&*x, &*y),
        _ => as_u64(a) == as_u64(b) || as_i64(a) == as_i64(b),
    }
}

fn eq_map(x: &BTreeMap<Key, Value>, y: &BTreeMap<Key, Value>) -> bool {
    for (k, v) in x {
        match y.get(k) {
            Some(ref w) => {
                if !eq(v, w) {
                    return false;
                }
            }
            None => return false,
        }
    }
    true
}
