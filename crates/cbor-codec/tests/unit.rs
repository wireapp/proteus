// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::value::{Int, Key, Text, Value};
use cbor::{Config, GenericDecoder};
use json::decoder::ReadIter;
use json::{DecodeResult, Decoder, FromJson, Json};
use rustc_serialize::base64::FromBase64;
use std::fs::File;

pub mod util;

struct TestVector {
    cbor: String,
    hex: String,
    #[allow(dead_code)]
    roundtrip: bool,
    decoded: Option<Json>,
    diagnostic: Option<Json>,
}

impl FromJson for TestVector {
    fn decode<I: Iterator<Item = char>>(d: &mut Decoder<I>) -> DecodeResult<TestVector> {
        use json::*;
        json::object! {
            let decoder = d;
            TestVector {
                cbor:       req. "cbor"       => d.string(),
                hex:        req. "hex"        => d.string(),
                roundtrip:  req. "roundtrip"  => d.bool(),
                decoded:    opt. "decoded"    => d.from_json(),
                diagnostic: opt. "diagnostic" => d.from_json()
            }
        }
    }
}

#[test]
fn int_min_max() {
    crate::util::identity(|mut e| e.i8(i8::MAX), |mut d| d.i8().unwrap() == i8::MAX);
    crate::util::identity(|mut e| e.i8(i8::MIN), |mut d| d.i8().unwrap() == i8::MIN);
    crate::util::identity(
        |mut e| e.i16(i16::MAX),
        |mut d| d.i16().unwrap() == i16::MAX,
    );
    crate::util::identity(
        |mut e| e.i16(i16::MIN),
        |mut d| d.i16().unwrap() == i16::MIN,
    );
    crate::util::identity(
        |mut e| e.i32(i32::MAX),
        |mut d| d.i32().unwrap() == i32::MAX,
    );
    crate::util::identity(
        |mut e| e.i32(i32::MIN),
        |mut d| d.i32().unwrap() == i32::MIN,
    );
    crate::util::identity(
        |mut e| e.i64(i64::MAX),
        |mut d| d.i64().unwrap() == i64::MAX,
    );
    crate::util::identity(
        |mut e| e.i64(i64::MIN),
        |mut d| d.i64().unwrap() == i64::MIN,
    );
    crate::util::identity(
        |mut e| e.int(Int::Neg(u64::MAX)),
        |mut d| d.int().unwrap() == Int::Neg(u64::MAX),
    );
    crate::util::identity(
        |mut e| e.int(Int::Pos(u64::MAX)),
        |mut d| d.int().unwrap().u64() == Some(u64::MAX),
    );
    assert_eq!(Some(i64::MIN), Int::Neg(i64::MAX as u64).i64());
    assert_eq!(Some(i64::MAX), Int::Pos(i64::MAX as u64).i64());
    assert_eq!(Some(u64::MIN), Int::Pos(u64::MIN).u64());
    assert_eq!(Some(u64::MAX), Int::Pos(u64::MAX).u64())
}

#[test]
fn test_all() {
    let iter = ReadIter::new(File::open("tests/appendix_a.json").unwrap());
    let test_vectors: Vec<TestVector> = Decoder::default(iter).from_json().unwrap();
    for v in test_vectors {
        let raw = v.cbor.from_base64().unwrap();
        let mut dec = GenericDecoder::new(Config::default(), &raw[..]);
        let val = dec.value().unwrap();
        if let Some(x) = v.decoded {
            if !eq(&x, &val) {
                panic!("{}: {:?} <> {:?}", v.hex, x, val)
            }
            continue;
        }
        if let Some(Json::String(ref x)) = v.diagnostic {
            if !diag(x, &val) {
                panic!("{}: {:?} <> {:?}", v.hex, x, val)
            }
        }
    }
}

fn eq(a: &Json, b: &Value) -> bool {
    match (a, b) {
        (&Json::Null, &Value::Null) => true,
        (&Json::Bool(x), &Value::Bool(y)) => x == y,
        (&Json::String(ref x), &Value::Text(Text::Text(ref y))) => x == y,
        (&Json::String(ref x), &Value::Text(Text::Chunks(ref y))) => {
            let mut s = String::new();
            for c in y {
                s.push_str(c)
            }
            x == &s
        }
        (&Json::Number(x), y) => util::as_f64(y)
            .map(|i| (x - i).abs() < f64::EPSILON)
            .unwrap_or(false),
        (&Json::Array(ref x), &Value::Array(ref y)) => {
            x.iter().zip(y.iter()).all(|(xi, yi)| eq(xi, yi))
        }
        (&Json::Object(ref x), &Value::Map(ref y)) => {
            for (k, v) in x {
                if let Some(w) = y.get(&Key::Text(Text::Text(k.clone()))) {
                    if !eq(v, w) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

// Note [diagnostic]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// At the moment we can not parse complete diagnostic syntax. That is why we
// only test a subset of the diagnostic values.
fn diag(a: &str, b: &Value) -> bool {
    match (a, b) {
        ("Infinity", &Value::F32(x)) => x == f32::INFINITY,
        ("Infinity", &Value::F64(x)) => x == f64::INFINITY,
        ("-Infinity", &Value::F32(x)) => x == -f32::INFINITY,
        ("-Infinity", &Value::F64(x)) => x == -f64::INFINITY,
        ("NaN", &Value::F32(x)) => x.is_nan(),
        ("NaN", &Value::F64(x)) => x.is_nan(),
        ("undefined", &Value::Undefined) => true,
        _ => true, // See note [diagnostic]
    }
}
