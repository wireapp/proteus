// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

//! This module defines the generic `Value` AST as well as
//! several  other types to represent CBOR values.
//! A `Cursor` can be used to deconstruct and traverse
//! a `Value`.

use crate::types::Tag;
use std::collections::{BTreeMap, LinkedList};
use std::i64;

/// The generic CBOR representation.
#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum Value {
    Array(Vec<Value>),
    Bool(bool),
    Break,
    Bytes(Bytes),
    F32(f32),
    F64(f64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    Int(Int),
    Map(BTreeMap<Key, Value>),
    Null,
    Simple(Simple),
    Tagged(Tag, Box<Value>),
    Text(Text),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Undefined,
}

/// Type to represent all possible CBOR integer values.
///
/// Since the encoding of negative integers (major type 1) follows
/// unsigned integers (major type 0), mapping negative integers
/// to `i8`, `i16`, `i32` or `i64` can result in integer overflows.
/// If all possible values should be handled, this type can be used.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Int {
    Neg(u64),
    Pos(u64),
}

impl Int {
    pub fn from_u64(n: u64) -> Int {
        Int::Pos(n)
    }

    pub fn from_i64(n: i64) -> Int {
        if n < 0 {
            Int::Neg(i64::abs(n) as u64 - 1)
        } else {
            Int::Pos(n as u64)
        }
    }

    /// Map this value to an `i64`. If the value does not
    /// fit within `[i64::MIN, i64::MAX]`, `None` is returned instead.
    pub fn i64(&self) -> Option<i64> {
        match *self {
            Int::Neg(n) if n <= i64::MAX as u64 => Some(-1 - n as i64),
            Int::Pos(n) if n <= i64::MAX as u64 => Some(n as i64),
            _ => None,
        }
    }

    /// Map this value to a `u64`. If the value is negative,
    /// `None` is returned instead.
    pub fn u64(&self) -> Option<u64> {
        match *self {
            Int::Pos(n) => Some(n),
            _ => None,
        }
    }
}

/// A unification of plain and indefinitly sized strings.
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub enum Text {
    Text(String),
    Chunks(LinkedList<String>),
}

/// A unification of plain an indefinitly sized byte strings.
#[derive(Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub enum Bytes {
    Bytes(Vec<u8>),
    Chunks(LinkedList<Vec<u8>>),
}

/// Most simple types (e.g. `bool` are covered elsewhere) but this
/// value captures those value ranges of CBOR type `Simple` (major 7)
/// which are either not assigned or reserved.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub enum Simple {
    Unassigned(u8),
    Reserved(u8),
}

/// CBOR allows heterogenous keys in objects. This enum unifies
/// all currently allowed key types.
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub enum Key {
    Bool(bool),
    Bytes(Bytes),
    Int(Int),
    Text(Text),
}

impl Key {
    pub fn u64(n: u64) -> Key {
        Key::Int(Int::from_u64(n))
    }

    pub fn i64(n: i64) -> Key {
        Key::Int(Int::from_i64(n))
    }
}

/// A `Cursor` allows conventient navigation in a `Value` AST.
/// `Value`s can be converted to native Rust types if possible and
/// collections can be traversed using `at` or `get`.
pub struct Cursor<'r> {
    value: Option<&'r Value>,
}

impl<'r> Cursor<'r> {
    pub fn new(v: &'r Value) -> Cursor<'r> {
        Cursor { value: Some(v) }
    }

    fn of(v: Option<&'r Value>) -> Cursor<'r> {
        Cursor { value: v }
    }

    pub fn at(&self, i: usize) -> Cursor<'r> {
        match self.value {
            Some(&Value::Array(ref a)) => Cursor::of(a.get(i)),
            _ => Cursor::of(None),
        }
    }

    pub fn get(&self, k: Key) -> Cursor<'r> {
        match self.value {
            Some(&Value::Map(ref m)) => Cursor::of(m.get(&k)),
            _ => Cursor::of(None),
        }
    }

    pub fn field(&self, s: &str) -> Cursor<'r> {
        self.get(Key::Text(Text::Text(String::from(s))))
    }

    pub fn value(&self) -> Option<&Value> {
        self.value
    }

    pub fn opt(&self) -> Option<Cursor<'r>> {
        match self.value {
            Some(&Value::Null) => None,
            Some(v) => Some(Cursor::new(v)),
            _ => None,
        }
    }

    pub fn maybe(&self) -> Option<Cursor<'r>> {
        match self.value {
            Some(&Value::Undefined) => None,
            Some(v) => Some(Cursor::new(v)),
            _ => None,
        }
    }

    pub fn bool(&self) -> Option<bool> {
        match self.value {
            Some(&Value::Bool(x)) => Some(x),
            _ => None,
        }
    }

    pub fn bytes(&self) -> Option<&Bytes> {
        match self.value {
            Some(&Value::Bytes(ref x)) => Some(x),
            _ => None,
        }
    }

    pub fn bytes_plain(&self) -> Option<&Vec<u8>> {
        match self.value {
            Some(&Value::Bytes(Bytes::Bytes(ref x))) => Some(x),
            _ => None,
        }
    }

    pub fn bytes_chunked(&self) -> Option<&LinkedList<Vec<u8>>> {
        match self.value {
            Some(&Value::Bytes(Bytes::Chunks(ref x))) => Some(x),
            _ => None,
        }
    }

    pub fn text(&self) -> Option<&Text> {
        match self.value {
            Some(&Value::Text(ref x)) => Some(x),
            _ => None,
        }
    }

    pub fn text_plain(&self) -> Option<&String> {
        match self.value {
            Some(&Value::Text(Text::Text(ref x))) => Some(x),
            _ => None,
        }
    }

    pub fn text_chunked(&self) -> Option<&LinkedList<String>> {
        match self.value {
            Some(&Value::Text(Text::Chunks(ref x))) => Some(x),
            _ => None,
        }
    }

    pub fn float32(&self) -> Option<f32> {
        match self.value {
            Some(&Value::F32(x)) => Some(x),
            _ => None,
        }
    }

    pub fn float64(&self) -> Option<f64> {
        match self.value {
            Some(&Value::F64(x)) => Some(x),
            _ => None,
        }
    }

    pub fn u8(&self) -> Option<u8> {
        match self.value {
            Some(&Value::U8(x)) => Some(x),
            _ => None,
        }
    }

    pub fn u16(&self) -> Option<u16> {
        match self.value {
            Some(&Value::U16(x)) => Some(x),
            _ => None,
        }
    }

    pub fn u32(&self) -> Option<u32> {
        match self.value {
            Some(&Value::U32(x)) => Some(x),
            _ => None,
        }
    }

    pub fn u64(&self) -> Option<u64> {
        match self.value {
            Some(&Value::U64(x)) => Some(x),
            _ => None,
        }
    }

    pub fn i8(&self) -> Option<i8> {
        match self.value {
            Some(&Value::I8(x)) => Some(x),
            _ => None,
        }
    }

    pub fn i16(&self) -> Option<i16> {
        match self.value {
            Some(&Value::I16(x)) => Some(x),
            _ => None,
        }
    }

    pub fn i32(&self) -> Option<i32> {
        match self.value {
            Some(&Value::I32(x)) => Some(x),
            _ => None,
        }
    }

    pub fn i64(&self) -> Option<i64> {
        match self.value {
            Some(&Value::I64(x)) => Some(x),
            _ => None,
        }
    }
}

/// Inspect the given `Value` which must be a `Value::Tagged` and
/// ensure that the `Tag` and type of value match according to
/// RFC 7049 section 2.4
pub fn check(value: &Value) -> bool {
    fn fun(t: Tag, b: &Value) -> bool {
        match (t, b) {
            (Tag::DateTime, &Value::Text(_)) => true,
            (Tag::Timestamp, &Value::U8(_)) => true,
            (Tag::Timestamp, &Value::U16(_)) => true,
            (Tag::Timestamp, &Value::U32(_)) => true,
            (Tag::Timestamp, &Value::U64(_)) => true,
            (Tag::Timestamp, &Value::I8(_)) => true,
            (Tag::Timestamp, &Value::I16(_)) => true,
            (Tag::Timestamp, &Value::I32(_)) => true,
            (Tag::Timestamp, &Value::I64(_)) => true,
            (Tag::Timestamp, &Value::F32(_)) => true,
            (Tag::Timestamp, &Value::F64(_)) => true,
            (Tag::Bignum, &Value::Bytes(_)) => true,
            (Tag::NegativeBignum, &Value::Bytes(_)) => true,
            (Tag::ToBase64, _) => true,
            (Tag::ToBase64Url, _) => true,
            (Tag::ToBase16, _) => true,
            (Tag::Cbor, &Value::Bytes(_)) => true,
            (Tag::Uri, &Value::Text(_)) => true,
            (Tag::Base64, &Value::Text(_)) => true,
            (Tag::Base64Url, &Value::Text(_)) => true,
            (Tag::Regex, &Value::Text(_)) => true,
            (Tag::Mime, &Value::Text(_)) => true,
            (Tag::CborSelf, _) => true,
            (Tag::Decimal, &Value::Array(ref a)) | (Tag::Bigfloat, &Value::Array(ref a)) => {
                if a.len() != 2 {
                    return false;
                }
                let is_integral = |v: &Value| {
                    matches!(
                        *v,
                        Value::U8(_)
                            | Value::U16(_)
                            | Value::U32(_)
                            | Value::U64(_)
                            | Value::I8(_)
                            | Value::I16(_)
                            | Value::I32(_)
                            | Value::I64(_)
                    )
                };
                let is_bignum = |v: &Value| fun(Tag::Bignum, v) || fun(Tag::NegativeBignum, v);
                let e = &a[0];
                let m = &a[1];
                is_integral(e) && (is_integral(m) || is_bignum(m))
            }
            (Tag::Unassigned(_), _) => true,
            _ => false,
        }
    }

    match *value {
        Value::Tagged(t, ref b) => fun(t, b),
        _ => false,
    }
}
