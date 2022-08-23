// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use cbor::{Config, Decoder, Encoder, EncodeResult};
use cbor::value::Value;
use std::io::Cursor;

pub fn identity<F, G>(enc: F, dec: G) -> bool
where F: Fn(Encoder<&mut Cursor<Vec<u8>>>) -> EncodeResult,
      G: Fn(Decoder<&mut Cursor<Vec<u8>>>) -> bool
{
    let mut buffer = Cursor::new(Vec::new());
    match enc(Encoder::new(&mut buffer)) {
        Ok(_)  => (),
        Err(e) => panic!("encoder failure: {:?}", e)
    }
    buffer.set_position(0);
    dec(Decoder::new(Config::default(), &mut buffer))
}

pub fn as_u64(x: &Value) -> Option<u64> {
    match *x {
        Value::U8(n)  => Some(n as u64),
        Value::U16(n) => Some(n as u64),
        Value::U32(n) => Some(n as u64),
        Value::U64(n) => Some(n),
        Value::I8(n)  if n >= 0 => Some(n as u64),
        Value::I16(n) if n >= 0 => Some(n as u64),
        Value::I32(n) if n >= 0 => Some(n as u64),
        Value::I64(n) if n >= 0 => Some(n as u64),
        _             => None
    }
}

pub fn as_i64(x: &Value) -> Option<i64> {
    match *x {
        Value::I8(n)  => Some(n as i64),
        Value::I16(n) => Some(n as i64),
        Value::I32(n) => Some(n as i64),
        Value::I64(n) => Some(n),
        _             => None
    }
}

pub fn as_f64(x: &Value) -> Option<f64> {
    match *x {
        Value::U8(n)  => Some(n as f64),
        Value::U16(n) => Some(n as f64),
        Value::U32(n) => Some(n as f64),
        Value::U64(n) => Some(n as f64),
        Value::I8(n)  => Some(n as f64),
        Value::I16(n) => Some(n as f64),
        Value::I32(n) => Some(n as f64),
        Value::I64(n) => Some(n as f64),
        Value::F32(n) => Some(n as f64),
        Value::F64(n) => Some(n),
        _             => None
    }
}

