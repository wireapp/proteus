// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

//! CBOR types and tags definitions.

use byteorder::ReadBytesExt;
use std::io::Error;

/// The CBOR types.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub enum Type {
    Array,
    Bool,
    Break,
    Bytes,
    Float16,
    Float32,
    Float64,
    Int16,
    Int32,
    Int64,
    Int8,
    Null,
    Object,
    Tagged,
    Text,
    UInt16,
    UInt32,
    UInt64,
    UInt8,
    Undefined,
    Unknown { major: u8, info: u8 },
    Reserved { major: u8, info: u8 },
    Unassigned { major: u8, info: u8 },
}

impl Type {
    pub fn major(&self) -> u8 {
        match *self {
            Type::Array => 4,
            Type::Bool => 7,
            Type::Break => 7,
            Type::Bytes => 2,
            Type::Float16 => 7,
            Type::Float32 => 7,
            Type::Float64 => 7,
            Type::Int16 => 1,
            Type::Int32 => 1,
            Type::Int64 => 1,
            Type::Int8 => 1,
            Type::Null => 7,
            Type::Object => 5,
            Type::Tagged => 6,
            Type::Text => 3,
            Type::UInt16 => 0,
            Type::UInt32 => 0,
            Type::UInt64 => 0,
            Type::UInt8 => 0,
            Type::Undefined => 7,
            Type::Unknown { major: m, .. } => m,
            Type::Reserved { major: m, .. } => m,
            Type::Unassigned { major: m, .. } => m,
        }
    }

    pub fn read<R: ReadBytesExt>(r: &mut R) -> Result<(Type, u8), Error> {
        let b = r.read_u8()?;
        match ((b & 0b1110_0000) >> 5, b & 0b0001_1111) {
            (0, a @ 0..=24) => Ok((Type::UInt8, a)),
            (0, 25) => Ok((Type::UInt16, 25)),
            (0, 26) => Ok((Type::UInt32, 26)),
            (0, 27) => Ok((Type::UInt64, 27)),
            (1, a @ 0..=24) => Ok((Type::Int8, a)),
            (1, 25) => Ok((Type::Int16, 25)),
            (1, 26) => Ok((Type::Int32, 26)),
            (1, 27) => Ok((Type::Int64, 27)),
            (2, a) => Ok((Type::Bytes, a)),
            (3, a) => Ok((Type::Text, a)),
            (4, a) => Ok((Type::Array, a)),
            (5, a) => Ok((Type::Object, a)),
            (6, a) => Ok((Type::Tagged, a)),
            (7, a @ 0..=19) => Ok((Type::Unassigned { major: 7, info: a }, a)),
            (7, 20) => Ok((Type::Bool, 20)),
            (7, 21) => Ok((Type::Bool, 21)),
            (7, 22) => Ok((Type::Null, 22)),
            (7, 23) => Ok((Type::Undefined, 23)),
            (7, 24) => match r.read_u8()? {
                a @ 0..=31 => Ok((Type::Reserved { major: 7, info: a }, a)),
                a => Ok((Type::Unassigned { major: 7, info: a }, a)),
            },
            (7, 25) => Ok((Type::Float16, 25)),
            (7, 26) => Ok((Type::Float32, 26)),
            (7, 27) => Ok((Type::Float64, 27)),
            (7, a @ 28..=30) => Ok((Type::Unassigned { major: 7, info: a }, a)),
            (7, 31) => Ok((Type::Break, 31)),
            (m, a) => Ok((Type::Unknown { major: m, info: a }, a)),
        }
    }
}

/// CBOR tags (corresponding to `Type::Tagged`).
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
pub enum Tag {
    DateTime,
    Timestamp,
    Bignum,
    NegativeBignum,
    Decimal,
    Bigfloat,
    Unassigned(u64),
    ToBase64Url,
    ToBase64,
    ToBase16,
    Cbor,
    Uri,
    Base64Url,
    Base64,
    Regex,
    Mime,
    CborSelf,
}

impl Tag {
    pub fn of(x: u64) -> Tag {
        match x {
            0 => Tag::DateTime,
            1 => Tag::Timestamp,
            2 => Tag::Bignum,
            3 => Tag::NegativeBignum,
            4 => Tag::Decimal,
            5 => Tag::Bigfloat,
            21 => Tag::ToBase64Url,
            22 => Tag::ToBase64,
            23 => Tag::ToBase16,
            24 => Tag::Cbor,
            32 => Tag::Uri,
            33 => Tag::Base64Url,
            34 => Tag::Base64,
            35 => Tag::Regex,
            36 => Tag::Mime,
            55799 => Tag::CborSelf,
            _ => Tag::Unassigned(x),
        }
    }

    pub fn to(&self) -> u64 {
        match *self {
            Tag::DateTime => 0,
            Tag::Timestamp => 1,
            Tag::Bignum => 2,
            Tag::NegativeBignum => 3,
            Tag::Decimal => 4,
            Tag::Bigfloat => 5,
            Tag::ToBase64Url => 21,
            Tag::ToBase64 => 22,
            Tag::ToBase16 => 23,
            Tag::Cbor => 24,
            Tag::Uri => 32,
            Tag::Base64Url => 33,
            Tag::Base64 => 34,
            Tag::Regex => 35,
            Tag::Mime => 36,
            Tag::CborSelf => 55799,
            Tag::Unassigned(x) => x,
        }
    }
}
