// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

//! CBOR ([RFC 7049](http://tools.ietf.org/html/rfc7049))
//! decoder implementation supporting the following features:
//!
//! - Generic decoding using an intermediate representation
//! - Tag validation
//! - Resource limits (e.g. maximum nesting level)
//! - Direct decoding into Rust types
//! - Indefinite sized bytes, strings, arrays and objects
//!
//! The module is structured as follows:
//!
//! 1. `Kernel` contains the basic decoding functionality, capable of
//! decoding simple unstructured types.
//! 2. `Decoder` directly decodes into native Rust types.
//! 3. `GenericDecoder` handles arbitrary CBOR items and decodes them
//! into an `Value` AST.
//!
//! # Example 1: Direct decoding
//!
//! ```
//! use cbor::{Config, Decoder};
//! use std::io::Cursor;
//!
//! let mut d = Decoder::new(Config::default(), Cursor::new(vec![0u8]));
//! assert_eq!(Some(0), d.u64().ok())
//! ```
//!
//! # Example 2: Direct decoding (nested array)
//!
//! ```
//! extern crate cbor;
//! extern crate rustc_serialize;
//!
//! use cbor::{Config, Decoder};
//! use rustc_serialize::hex::FromHex;
//! use std::io::Cursor;
//!
//! fn main() {
//!     let input   = Cursor::new("828301020383010203".from_hex().unwrap());
//!     let mut dec = Decoder::new(Config::default(), input);
//!     let mut res = Vec::new();
//!     for _ in 0 .. dec.array().unwrap() {
//!         let mut vec = Vec::new();
//!         for _ in 0 .. dec.array().unwrap() {
//!             vec.push(dec.u8().unwrap())
//!         }
//!         res.push(vec)
//!     }
//!     assert_eq!(vec![vec![1, 2, 3], vec![1, 2, 3]], res)
//! }
//! ```
//!
//! # Example 3: Generic decoding
//!
//! ```
//! extern crate cbor;
//! extern crate rustc_serialize;
//!
//! use cbor::{Config, GenericDecoder};
//! use cbor::value::{self, Key};
//! use rustc_serialize::hex::FromHex;
//! use std::io::Cursor;
//!
//! fn main() {
//!     let input = Cursor::new("a2616101028103".from_hex().unwrap());
//!     let mut d = GenericDecoder::new(Config::default(), input);
//!     let value = d.value().unwrap();
//!     let     c = value::Cursor::new(&value);
//!     assert_eq!(Some(1), c.field("a").u8());
//!     assert_eq!(Some(3), c.get(Key::u64(2)).at(0).u8())
//! }
//! ```
//!
//! # Example 4: Direct decoding (optional value)
//!
//! ```
//! use cbor::{opt, Config, Decoder};
//! use std::io::Cursor;
//!
//! let mut d = Decoder::new(Config::default(), Cursor::new(vec![0xF6]));
//! assert_eq!(None, opt(d.u8()).unwrap())
//! ```

use crate::skip::Skip;
use crate::slice::{ReadSlice, ReadSliceError};
use crate::types::{Tag, Type};
use crate::value::{self, Bytes, Int, Key, Simple, Text, Value};
use byteorder::{BigEndian, ReadBytesExt};
use std::collections::{BTreeMap, LinkedList};
use std::error::Error;
use std::f32;
use std::fmt;
use std::io;
use std::str::{from_utf8, Utf8Error};
use std::string;
use std::{i16, i32, i64, i8};

// Decoder Configuration ////////////////////////////////////////////////////

/// `Config` contains various settings which limit resource consumption
/// or enable certain validation options. Please note that the various
/// maximum length/size values apply to an individual element only.
///
/// This is mainly to prevent attackers from providing CBOR values whose
/// length is larger than the available memory. In combination the memory
/// consumption can still become large and it is best to limit the incoming
/// bytes to a specific upper bound, e.g. by using `std::io::Take`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Maximum number of array elements
    pub max_len_array: usize,
    /// Maximum length of a byte string
    pub max_len_bytes: usize,
    /// Maximum length of a string
    pub max_len_text: usize,
    /// Maximum number of object fields
    pub max_size_map: usize,
    /// Maximum recursion steps when decoder `Value`s
    pub max_nesting: usize,
    /// Ignore `Tag`s when decoding `Value`s
    pub skip_tags: bool,
    /// Validate `Value` type matches `Tag`.
    pub check_tags: bool,
}

const DEFAULT_CONFIG: Config = Config {
    max_len_array: 1000,
    max_len_bytes: 0x500000,
    max_len_text: 0x500000,
    max_size_map: 1000,
    max_nesting: 16,
    skip_tags: false,
    check_tags: true,
};

impl Default for Config {
    /// Create default configuration with
    ///
    /// - `max_len_array` = 1000
    /// - `max_len_bytes` = 5 MB
    /// - `max_len_text` = 5 MB
    /// - `max_size_map` = 1000
    /// - `max_nesting` = 16
    /// - `skip_tags` = false
    /// - `check_tags` = true
    fn default() -> Config {
        DEFAULT_CONFIG
    }
}

// Decode Error Type ////////////////////////////////////////////////////////

pub type DecodeResult<A> = Result<A, DecodeError>;

#[derive(Debug)]
pub enum DecodeError {
    /// An object contains the same key multiple times
    DuplicateKey(Key),
    /// The signed integer is greater that its max value
    IntOverflow(u64),
    /// The decoded `Value` can not serve as a `Key` in an object
    InvalidKey(Value),
    /// The type of `Value` is not what is expected for a `Tag`
    InvalidTag(Value),
    /// The string is not encoded in UTF-8
    InvalidUtf8(Utf8Error),
    /// Some I/O error
    IoError(io::Error),
    /// The maximum configured length is exceeded
    TooLong { max: usize, actual: u64 },
    /// `Value`s are nested deeper than the configured maximum
    TooNested,
    /// The end of file has been encountered unexpectedly
    UnexpectedEOF,
    /// An unexpected type has been encountered
    UnexpectedType { datatype: Type, info: u8 },
    /// A break was encountered at some unexpected point while
    /// decoding an indefinite object.
    UnexpectedBreak,
    /// Some other error.
    Other(Box<dyn Error + Send + Sync>),
}

/// When decoding an optional item, i.e. a `Null` value has to be
/// considered, this function will map `Null` to `None` and any
/// other value to `Some(value)`.
pub fn opt<A>(r: DecodeResult<A>) -> DecodeResult<Option<A>> {
    match r {
        Ok(x) => Ok(Some(x)),
        Err(e) => {
            if is_null(&e) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// When decoding an item which may be `Undefined` this function
/// will map `Undefined` to `None` and any other value to `Some(value)`.
pub fn maybe<A>(r: DecodeResult<A>) -> DecodeResult<Option<A>> {
    match r {
        Ok(x) => Ok(Some(x)),
        Err(e) => {
            if is_undefined(&e) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// When decoding an indefinite item, every element item can be a `Break`
/// value. By wrapping it in `or_break`, this case can be handled more
/// conveniently.
pub fn or_break<A>(r: DecodeResult<A>) -> DecodeResult<Option<A>> {
    match r {
        Ok(x) => Ok(Some(x)),
        Err(e) => {
            if is_break(&e) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

fn is_break(e: &DecodeError) -> bool {
    matches!(
        *e,
        DecodeError::UnexpectedType {
            datatype: Type::Break,
            ..
        }
    )
}

fn is_null(e: &DecodeError) -> bool {
    matches!(
        *e,
        DecodeError::UnexpectedType {
            datatype: Type::Null,
            ..
        }
    )
}

fn is_undefined(e: &DecodeError) -> bool {
    matches!(
        *e,
        DecodeError::UnexpectedType {
            datatype: Type::Undefined,
            ..
        }
    )
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            DecodeError::DuplicateKey(ref k) => write!(f, "DecodeError: duplicate key: {k:?}"),
            DecodeError::IntOverflow(n) => write!(f, "DecodeError: integer overflow: {n}"),
            DecodeError::InvalidKey(ref k) => {
                write!(f, "DecodeError: unsuitable map key: {k:?}")
            }
            DecodeError::InvalidTag(ref v) => {
                write!(f, "DecodeError: value does not match tag: {v:?}")
            }
            DecodeError::InvalidUtf8(ref e) => {
                write!(f, "DecodeError: Invalid UTF-8 encoding: {e}")
            }
            DecodeError::IoError(ref e) => write!(f, "DecodeError: I/O error: {e}"),
            DecodeError::TooNested => write!(f, "DecodeError: value is too nested"),
            DecodeError::UnexpectedEOF => write!(f, "DecodeError: unexpected end-of-file"),
            DecodeError::UnexpectedBreak => write!(f, "DecodeError: unexpected break"),
            DecodeError::Other(ref e) => write!(f, "DecodeError: other: {e:?}"),
            DecodeError::TooLong { max: m, actual: a } => {
                write!(f, "DecodeError: value is too long {a} (max={m})")
            }
            DecodeError::UnexpectedType {
                datatype: t,
                info: i,
            } => write!(f, "DecodeError: unexpected type {t:?} (info={i})"),
        }
    }
}

impl Error for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::DuplicateKey(_) => "duplicate key in objects",
            DecodeError::IntOverflow(_) => "integer overflow",
            DecodeError::InvalidKey(_) => "invalid object key",
            DecodeError::InvalidTag(_) => "invalid tag",
            DecodeError::InvalidUtf8(_) => "invalid utf-8",
            DecodeError::IoError(_) => "i/o error",
            DecodeError::TooNested => "too deeply nested objects/arrays",
            DecodeError::UnexpectedEOF => "unexpected eof",
            DecodeError::UnexpectedBreak => "unexpected break",
            DecodeError::Other(_) => "other error",
            DecodeError::TooLong { .. } => "value is too long",
            DecodeError::UnexpectedType { .. } => "unexpected type",
        }
    }

    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            DecodeError::IoError(ref e) => Some(e),
            DecodeError::InvalidUtf8(ref e) => Some(e),
            DecodeError::Other(ref e) => Some(&**e),
            _ => None,
        }
    }
}

impl From<io::Error> for DecodeError {
    fn from(e: io::Error) -> DecodeError {
        DecodeError::IoError(e)
    }
}

impl From<string::FromUtf8Error> for DecodeError {
    fn from(e: string::FromUtf8Error) -> DecodeError {
        DecodeError::InvalidUtf8(e.utf8_error())
    }
}

impl From<Utf8Error> for DecodeError {
    fn from(e: Utf8Error) -> DecodeError {
        DecodeError::InvalidUtf8(e)
    }
}

impl From<ReadSliceError> for DecodeError {
    fn from(e: ReadSliceError) -> DecodeError {
        match e {
            ReadSliceError::InsufficientData => DecodeError::UnexpectedEOF,
            ReadSliceError::IoError(e) => DecodeError::IoError(e),
        }
    }
}

// Macros ///////////////////////////////////////////////////////////////////

// Like `read_signed` but always using `read_u8`
macro_rules! read_signed_byte {
    ($this: ident, $from_type: ty, $to: ident, $to_type: ty) => {{
        $this.reader.read_u8().map_err(From::from).and_then(|n| {
            if n > $to::MAX as $from_type {
                Err(DecodeError::IntOverflow(n as u64))
            } else {
                Ok(-1 - n as $to_type)
            }
        })
    }};
}

// Read from reader, check value range and map to negative integer.
macro_rules! read_signed {
    ($this: ident, $from: ident, $from_type: ty, $to: ident, $to_type: ty) => {{
        $this
            .reader
            .$from::<BigEndian>()
            .map_err(From::from)
            .and_then(|n| {
                if n > $to::MAX as $from_type {
                    Err(DecodeError::IntOverflow(n as u64))
                } else {
                    Ok(-1 - n as $to_type)
                }
            })
    }};
}

// Read unsigned integer, check value range and cast to target type.
macro_rules! cast_unsigned {
    ($this: ident, $from: ident, $info: ident, $from_type: ty, $to: ident, $to_type: ty) => {{
        $this.$from($info).and_then(|n| {
            if n > $to::MAX as $from_type {
                Err(DecodeError::IntOverflow(n as u64))
            } else {
                Ok(n as $to_type)
            }
        })
    }};
}

// Decoder Kernel ///////////////////////////////////////////////////////////

pub type TypeInfo = (Type, u8);

/// This decoding kernel reads from an underlying `std::io::Read` type
/// primitive CBOR values such as unsigned and signed integers as well
/// as raw bytes.
/// It forms the basis on which `Decoder` and `GenericDecoder` add logic
/// for handling `Tag`s, heterogenous data and generic value decoding.
pub struct Kernel<R> {
    reader: R,
}

impl<R: ReadBytesExt> Kernel<R> {
    pub fn new(r: R) -> Kernel<R> {
        Kernel { reader: r }
    }

    pub fn into_reader(self) -> R {
        self.reader
    }

    pub fn typeinfo(&mut self) -> DecodeResult<TypeInfo> {
        Type::read(&mut self.reader).map_err(From::from)
    }

    pub fn simple(&mut self, ti: &TypeInfo) -> DecodeResult<Simple> {
        match ti.0 {
            Type::Unassigned { major: 7, info: a } => Ok(Simple::Unassigned(a)),
            Type::Reserved { major: 7, info: a } => Ok(Simple::Reserved(a)),
            _ => unexpected_type(ti),
        }
    }

    pub fn bool(&mut self, ti: &TypeInfo) -> DecodeResult<bool> {
        match *ti {
            (Type::Bool, 20) => Ok(false),
            (Type::Bool, 21) => Ok(true),
            _ => unexpected_type(ti),
        }
    }

    pub fn u8(&mut self, ti: &TypeInfo) -> DecodeResult<u8> {
        match *ti {
            (Type::UInt8, n @ 0..=23) => Ok(n),
            (Type::UInt8, 24) => self.reader.read_u8().map_err(From::from),
            _ => unexpected_type(ti),
        }
    }

    pub fn u16(&mut self, ti: &TypeInfo) -> DecodeResult<u16> {
        match *ti {
            (Type::UInt8, n @ 0..=23) => Ok(n as u16),
            (Type::UInt8, 24) => self.reader.read_u8().map(|n| n as u16).map_err(From::from),
            (Type::UInt16, 25) => self.reader.read_u16::<BigEndian>().map_err(From::from),
            _ => unexpected_type(ti),
        }
    }

    pub fn u32(&mut self, ti: &TypeInfo) -> DecodeResult<u32> {
        match *ti {
            (Type::UInt8, n @ 0..=23) => Ok(n as u32),
            (Type::UInt8, 24) => self.reader.read_u8().map(|n| n as u32).map_err(From::from),
            (Type::UInt16, 25) => self
                .reader
                .read_u16::<BigEndian>()
                .map(|n| n as u32)
                .map_err(From::from),
            (Type::UInt32, 26) => self.reader.read_u32::<BigEndian>().map_err(From::from),
            _ => unexpected_type(ti),
        }
    }

    pub fn u64(&mut self, ti: &TypeInfo) -> DecodeResult<u64> {
        match *ti {
            (Type::UInt8, n @ 0..=23) => Ok(n as u64),
            (Type::UInt8, 24) => self.reader.read_u8().map(|n| n as u64).map_err(From::from),
            (Type::UInt16, 25) => self
                .reader
                .read_u16::<BigEndian>()
                .map(|n| n as u64)
                .map_err(From::from),
            (Type::UInt32, 26) => self
                .reader
                .read_u32::<BigEndian>()
                .map(|n| n as u64)
                .map_err(From::from),
            (Type::UInt64, 27) => self.reader.read_u64::<BigEndian>().map_err(From::from),
            _ => unexpected_type(ti),
        }
    }

    pub fn i8(&mut self, ti: &TypeInfo) -> DecodeResult<i8> {
        match *ti {
            (Type::Int8, n @ 0..=23) => Ok(-1 - n as i8),
            (Type::Int8, 24) => read_signed_byte!(self, u8, i8, i8),
            (Type::UInt8, _) => cast_unsigned!(self, u8, ti, u8, i8, i8),
            _ => unexpected_type(ti),
        }
    }

    pub fn i16(&mut self, ti: &TypeInfo) -> DecodeResult<i16> {
        match *ti {
            (Type::Int8, n @ 0..=23) => Ok(-1 - n as i16),
            (Type::Int8, 24) => read_signed_byte!(self, u8, i16, i16),
            (Type::Int16, 25) => read_signed!(self, read_u16, u16, i16, i16),
            (Type::UInt8, _) => cast_unsigned!(self, u8, ti, u8, i16, i16),
            (Type::UInt16, _) => cast_unsigned!(self, u16, ti, u16, i16, i16),
            _ => unexpected_type(ti),
        }
    }

    pub fn i32(&mut self, ti: &TypeInfo) -> DecodeResult<i32> {
        match *ti {
            (Type::Int8, n @ 0..=23) => Ok(-1 - n as i32),
            (Type::Int8, 24) => read_signed_byte!(self, u8, i32, i32),
            (Type::Int16, 25) => read_signed!(self, read_u16, u16, i32, i32),
            (Type::Int32, 26) => read_signed!(self, read_u32, u32, i32, i32),
            (Type::UInt8, _) => cast_unsigned!(self, u8, ti, u8, i32, i32),
            (Type::UInt16, _) => cast_unsigned!(self, u16, ti, u16, i32, i32),
            (Type::UInt32, _) => cast_unsigned!(self, u32, ti, u32, i32, i32),
            _ => unexpected_type(ti),
        }
    }

    pub fn i64(&mut self, ti: &TypeInfo) -> DecodeResult<i64> {
        match *ti {
            (Type::Int8, n @ 0..=23) => Ok(-1 - n as i64),
            (Type::Int8, 24) => read_signed_byte!(self, u8, i64, i64),
            (Type::Int16, 25) => read_signed!(self, read_u16, u16, i64, i64),
            (Type::Int32, 26) => read_signed!(self, read_u32, u32, i64, i64),
            (Type::Int64, 27) => read_signed!(self, read_u64, u64, i64, i64),
            (Type::UInt8, _) => cast_unsigned!(self, u8, ti, u8, i64, i64),
            (Type::UInt16, _) => cast_unsigned!(self, u16, ti, u16, i64, i64),
            (Type::UInt32, _) => cast_unsigned!(self, u32, ti, u32, i64, i64),
            (Type::UInt64, _) => cast_unsigned!(self, u64, ti, u64, i64, i64),
            _ => unexpected_type(ti),
        }
    }

    pub fn int(&mut self, ti: &TypeInfo) -> DecodeResult<Int> {
        match *ti {
            (Type::Int8, a) | (Type::Int16, a) | (Type::Int32, a) | (Type::Int64, a) => {
                self.unsigned(a).map(Int::Neg)
            }

            (Type::UInt8, a) | (Type::UInt16, a) | (Type::UInt32, a) | (Type::UInt64, a) => {
                self.unsigned(a).map(Int::Pos)
            }

            _ => unexpected_type(ti),
        }
    }

    pub fn f16(&mut self, ti: &TypeInfo) -> DecodeResult<f32> {
        match ti.0 {
            Type::Float16 => {
                // Copied from RFC 7049 Appendix D:
                let f16 = half::f16::from_bits(self.reader.read_u16::<BigEndian>()?);
                Ok(f16.to_f32())
            }
            _ => unexpected_type(ti),
        }
    }

    pub fn f32(&mut self, ti: &TypeInfo) -> DecodeResult<f32> {
        match ti.0 {
            Type::Float32 => self.reader.read_f32::<BigEndian>().map_err(From::from),
            _ => unexpected_type(ti),
        }
    }

    pub fn f64(&mut self, ti: &TypeInfo) -> DecodeResult<f64> {
        match ti.0 {
            Type::Float64 => self.reader.read_f64::<BigEndian>().map_err(From::from),
            _ => unexpected_type(ti),
        }
    }

    /// Decode `first` and potentially the following bytes as an
    /// unsigned value following the rules of major type 0.
    pub fn unsigned(&mut self, first: u8) -> DecodeResult<u64> {
        match first {
            n @ 0..=23 => Ok(n as u64),
            24 => self.reader.read_u8().map(|n| n as u64).map_err(From::from),
            25 => self
                .reader
                .read_u16::<BigEndian>()
                .map(|n| n as u64)
                .map_err(From::from),
            26 => self
                .reader
                .read_u32::<BigEndian>()
                .map(|n| n as u64)
                .map_err(From::from),
            27 => self.reader.read_u64::<BigEndian>().map_err(From::from),
            _ => unexpected_type(&(Type::UInt64, first)),
        }
    }

    /// Read `begin` as the length and return that many raw bytes.
    ///
    /// If length is greater than the given `max_len`, `DecodeError::TooLong`
    /// is returned instead.
    pub fn raw_data(&mut self, begin: u8, max_len: usize) -> DecodeResult<Vec<u8>> {
        let len = self.unsigned(begin)?;
        if len > max_len as u64 {
            return Err(DecodeError::TooLong {
                max: max_len,
                actual: len,
            });
        }
        let n = len as usize;
        let mut v = vec![0u8; n];
        let mut i = 0;
        while i < n {
            match self.reader.read(&mut v[i..]) {
                Ok(0) => return Err(DecodeError::UnexpectedEOF),
                Ok(j) => i += j,
                Err(e) => {
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(DecodeError::IoError(e));
                    }
                }
            }
        }
        Ok(v)
    }

    /// Read `begin` as the length and read that many raw bytes into `buf`.
    ///
    /// If length is greater than the given buffer, `DecodeError::TooLong`
    /// is returned instead.
    pub fn read_raw_data(&mut self, begin: u8, buf: &mut [u8]) -> DecodeResult<usize> {
        let len = self.unsigned(begin)?;
        if len > buf.len() as u64 {
            return Err(DecodeError::TooLong {
                max: buf.len(),
                actual: len,
            });
        }
        let n = len as usize;
        let mut i = 0;
        while i < n {
            match self.reader.read(&mut buf[i..]) {
                Ok(0) => return Err(DecodeError::UnexpectedEOF),
                Ok(j) => i += j,
                Err(e) => {
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(DecodeError::IoError(e));
                    }
                }
            }
        }
        Ok(n)
    }
}

impl<R: ReadBytesExt + ReadSlice> Kernel<R> {
    /// Read `begin` as the length and return that many raw bytes as a slice.
    ///
    /// If length is greater than the given `max_len`, `DecodeError::TooLong`
    /// is returned instead.
    pub fn raw_slice(&mut self, begin: u8, max_len: usize) -> DecodeResult<&[u8]> {
        let len = self.unsigned(begin)?;
        if len > max_len as u64 {
            return Err(DecodeError::TooLong {
                max: max_len,
                actual: len,
            });
        }
        self.reader.read_slice(len as usize).map_err(From::from)
    }
}

fn unexpected_type<A>(ti: &TypeInfo) -> DecodeResult<A> {
    Err(DecodeError::UnexpectedType {
        datatype: ti.0,
        info: ti.1,
    })
}

// Decoder //////////////////////////////////////////////////////////////////

/// The actual decoder type definition
pub struct Decoder<R> {
    kernel: Kernel<R>,
    config: Config,
}

impl<R: ReadBytesExt> Decoder<R> {
    pub fn new(c: Config, r: R) -> Decoder<R> {
        Decoder {
            kernel: Kernel::new(r),
            config: c,
        }
    }

    pub fn into_reader(self) -> R {
        self.kernel.into_reader()
    }

    pub fn kernel(&mut self) -> &mut Kernel<R> {
        &mut self.kernel
    }

    pub fn simple(&mut self) -> DecodeResult<Simple> {
        self.typeinfo().and_then(|ti| self.kernel.simple(&ti))
    }

    pub fn bool(&mut self) -> DecodeResult<bool> {
        self.typeinfo().and_then(|ti| self.kernel.bool(&ti))
    }

    pub fn u8(&mut self) -> DecodeResult<u8> {
        self.typeinfo().and_then(|ti| self.kernel.u8(&ti))
    }

    pub fn u16(&mut self) -> DecodeResult<u16> {
        self.typeinfo().and_then(|ti| self.kernel.u16(&ti))
    }

    pub fn u32(&mut self) -> DecodeResult<u32> {
        self.typeinfo().and_then(|ti| self.kernel.u32(&ti))
    }

    pub fn u64(&mut self) -> DecodeResult<u64> {
        self.typeinfo().and_then(|ti| self.kernel.u64(&ti))
    }

    pub fn i8(&mut self) -> DecodeResult<i8> {
        self.typeinfo().and_then(|ti| self.kernel.i8(&ti))
    }

    pub fn i16(&mut self) -> DecodeResult<i16> {
        self.typeinfo().and_then(|ti| self.kernel.i16(&ti))
    }

    pub fn i32(&mut self) -> DecodeResult<i32> {
        self.typeinfo().and_then(|ti| self.kernel.i32(&ti))
    }

    pub fn i64(&mut self) -> DecodeResult<i64> {
        self.typeinfo().and_then(|ti| self.kernel.i64(&ti))
    }

    pub fn int(&mut self) -> DecodeResult<Int> {
        self.typeinfo().and_then(|ti| self.kernel.int(&ti))
    }

    pub fn f16(&mut self) -> DecodeResult<f32> {
        self.typeinfo().and_then(|ti| self.kernel.f16(&ti))
    }

    pub fn f32(&mut self) -> DecodeResult<f32> {
        self.typeinfo().and_then(|ti| self.kernel.f32(&ti))
    }

    pub fn f64(&mut self) -> DecodeResult<f64> {
        self.typeinfo().and_then(|ti| self.kernel.f64(&ti))
    }

    /// Decode a single byte string into the given buffer.
    ///
    /// The provided buffer must be large enough to hold the entire
    /// byte string, otherwise an error is returned.
    ///
    /// Please note that indefinite byte strings are not supported by this
    /// method (Consider using `Decoder::bytes_iter()` for this use-case).
    pub fn read_bytes(&mut self, b: &mut [u8]) -> DecodeResult<usize> {
        match self.typeinfo()? {
            (Type::Bytes, 31) => unexpected_type(&(Type::Bytes, 31)),
            (Type::Bytes, i) => self.kernel.read_raw_data(i, b),
            ti => unexpected_type(&ti),
        }
    }

    /// Decode a single byte string.
    ///
    /// Please note that indefinite byte strings are not supported by this
    /// method (Consider using `Decoder::bytes_iter()` for this use-case).
    pub fn bytes(&mut self) -> DecodeResult<Vec<u8>> {
        match self.typeinfo()? {
            (Type::Bytes, 31) => unexpected_type(&(Type::Bytes, 31)),
            (Type::Bytes, i) => {
                let max = self.config.max_len_bytes;
                self.kernel.raw_data(i, max)
            }
            ti => unexpected_type(&ti),
        }
    }

    /// Decode an indefinite byte string.
    pub fn bytes_iter(&mut self) -> DecodeResult<BytesIter<R>> {
        match self.typeinfo()? {
            (Type::Bytes, 31) => Ok(BytesIter { decoder: self }),
            ti => unexpected_type(&ti),
        }
    }

    /// Decode a single UTF-8 encoded String.
    ///
    /// Please note that indefinite strings are not supported by this method
    /// (Consider using `Decoder::text_iter()` for this use-case).
    pub fn text(&mut self) -> DecodeResult<String> {
        match self.typeinfo()? {
            (Type::Text, 31) => unexpected_type(&(Type::Text, 31)),
            (Type::Text, i) => {
                let max = self.config.max_len_text;
                let data = self.kernel.raw_data(i, max)?;
                String::from_utf8(data).map_err(From::from)
            }
            ti => unexpected_type(&ti),
        }
    }

    /// Decode an indefinite string.
    pub fn text_iter(&mut self) -> DecodeResult<TextIter<R>> {
        match self.typeinfo()? {
            (Type::Text, 31) => Ok(TextIter { decoder: self }),
            ti => unexpected_type(&ti),
        }
    }

    /// Decode a `Tag`.
    /// If no tag is found an `UnexpectedType` error is returned.
    pub fn tag(&mut self) -> DecodeResult<Tag> {
        match self.kernel.typeinfo()? {
            (Type::Tagged, i) => self.kernel.unsigned(i).map(Tag::of),
            ti => unexpected_type(&ti),
        }
    }

    /// Decode the begin of an array. The length is returned unless it
    /// exceeds the configured maximum.
    ///
    /// Please note that indefinite arrays are not supported by this method
    /// (Consider using `Decoder::array_begin()` for this use-case).
    pub fn array(&mut self) -> DecodeResult<usize> {
        match self.typeinfo()? {
            (Type::Array, 31) => unexpected_type(&(Type::Array, 31)),
            (Type::Array, a) => {
                let len = self.kernel.unsigned(a)?;
                if len > self.config.max_len_array as u64 {
                    return Err(DecodeError::TooLong {
                        max: self.config.max_len_array,
                        actual: len,
                    });
                }
                Ok(len as usize)
            }
            ti => unexpected_type(&ti),
        }
    }

    /// Decode the begin of an indefinite array.
    /// After this one can continue decoding items, but a `Break` value
    /// will be encountered at some unknown point.
    ///
    /// (Consider using `or_break` around every decoding step within an
    /// indefinite array to handle this case).
    pub fn array_begin(&mut self) -> DecodeResult<()> {
        match self.typeinfo()? {
            (Type::Array, 31) => Ok(()),
            ti => unexpected_type(&ti),
        }
    }

    /// Decode the begin of an object. The size (number of key-value pairs)
    /// is returned unless it exceeds the configured maximum.
    ///
    /// Please note that indefinite objects are not supported by this method
    /// (Consider using `Decoder::object_begin` for this use-case).
    pub fn object(&mut self) -> DecodeResult<usize> {
        match self.typeinfo()? {
            (Type::Object, 31) => unexpected_type(&(Type::Object, 31)),
            (Type::Object, a) => {
                let len = self.kernel.unsigned(a)?;
                if len > self.config.max_size_map as u64 {
                    return Err(DecodeError::TooLong {
                        max: self.config.max_size_map,
                        actual: len,
                    });
                }
                Ok(len as usize)
            }
            ti => unexpected_type(&ti),
        }
    }

    /// Decode the begin of an indefinite object.
    /// After this one can continue decoding items, but a `Break` value
    /// will be encountered at some unknown point.
    ///
    /// (Consider using `or_break` around every decoding step within an
    /// indefinite object to handle this case).
    pub fn object_begin(&mut self) -> DecodeResult<()> {
        match self.typeinfo()? {
            (Type::Object, 31) => Ok(()),
            ti => unexpected_type(&ti),
        }
    }

    // Decode type information while skipping tags
    fn typeinfo(&mut self) -> DecodeResult<TypeInfo> {
        fn go<A: ReadBytesExt>(d: &mut Decoder<A>, level: usize) -> DecodeResult<TypeInfo> {
            if level == 0 {
                return Err(DecodeError::TooNested);
            }
            match d.kernel.typeinfo()? {
                (Type::Tagged, i) => d.kernel.unsigned(i).and(go(d, level - 1)),
                ti => Ok(ti),
            }
        }
        let start = self.config.max_nesting;
        go(self, start)
    }
}

impl<R: ReadBytesExt + Skip> Decoder<R> {
    /// Skip over a single CBOR value.
    ///
    /// Please note that this function does not validate the value hence
    /// it might not even be well-formed CBOR. Instead `skip` is an
    /// optimisation over `GenericDecoder::value()` and generally only
    /// determines as much information as necessary to safely skip a value
    /// without keeping all of it in memory.
    pub fn skip(&mut self) -> DecodeResult<()> {
        let start = self.config.max_nesting;
        self.skip_value(start).and(Ok(()))
    }

    fn skip_value(&mut self, level: usize) -> DecodeResult<bool> {
        if level == 0 {
            return Err(DecodeError::TooNested);
        }
        match self.typeinfo()? {
            (Type::UInt8, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::UInt16, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::UInt32, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::UInt64, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::Int8, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::Int16, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::Int32, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::Int64, n) => self.kernel.unsigned(n).and(Ok(true)),
            (Type::Bool, _) => Ok(true),
            (Type::Null, _) => Ok(true),
            (Type::Undefined, _) => Ok(true),
            (Type::Break, _) => Ok(false),
            (Type::Float16, _) => {
                self.kernel.reader.skip(2)?;
                Ok(true)
            }
            (Type::Float32, _) => {
                self.kernel.reader.skip(4)?;
                Ok(true)
            }
            (Type::Float64, _) => {
                self.kernel.reader.skip(8)?;
                Ok(true)
            }
            (Type::Bytes, 31) => self.skip_until_break(Type::Bytes).and(Ok(true)),
            (Type::Bytes, a) => {
                let n = self.kernel.unsigned(a)?;
                self.kernel.reader.skip(n)?;
                Ok(true)
            }
            (Type::Text, 31) => self.skip_until_break(Type::Text).and(Ok(true)),
            (Type::Text, a) => {
                let n = self.kernel.unsigned(a)?;
                self.kernel.reader.skip(n)?;
                Ok(true)
            }
            (Type::Array, 31) => {
                while self.skip_value(level - 1)? {}
                Ok(true)
            }
            (Type::Object, 31) => {
                while self.skip_value(level - 1)? {}
                Ok(true)
            }
            (Type::Array, a) => {
                let n = self.kernel.unsigned(a)?;
                for _ in 0..n {
                    self.skip_value(level - 1)?;
                }
                Ok(true)
            }
            (Type::Object, a) => {
                let n = self.kernel.unsigned(a)?;
                // n == number of fields => need to skip over keys and values.
                // Instead of doubling n we loop twice in order to avoid
                // overflowing n.
                for _ in 0..n {
                    self.skip_value(level - 1)?;
                }
                for _ in 0..n {
                    self.skip_value(level - 1)?;
                }
                Ok(true)
            }
            (Type::Unassigned { .. }, _) => Ok(true),
            (Type::Reserved { .. }, _) => Ok(true),
            ti @ (Type::Tagged, _) => unexpected_type(&ti),
            ti @ (Type::Unknown { .. }, _) => unexpected_type(&ti),
        }
    }

    // Skip over `Text` or `Bytes` until a `Break` is encountered.
    fn skip_until_break(&mut self, ty: Type) -> DecodeResult<()> {
        loop {
            let (t, a) = self.typeinfo()?;
            if t == Type::Break {
                break;
            }
            if t != ty || a == 31 {
                return unexpected_type(&(t, a));
            }
            let n = self.kernel.unsigned(a)?;
            self.kernel.reader.skip(n)?
        }
        Ok(())
    }
}

impl<R: ReadBytesExt + ReadSlice> Decoder<R> {
    /// Decode a single UTF-8 encoded String and borrow it from underlying
    /// buffer instead of allocating.
    ///
    /// Please note that indefinite strings are not supported by this method.
    pub fn text_borrow(&mut self) -> DecodeResult<&str> {
        match self.typeinfo()? {
            (Type::Text, 31) => unexpected_type(&(Type::Text, 31)),
            (Type::Text, i) => {
                let max = self.config.max_len_text;
                let data = self.kernel.raw_slice(i, max)?;
                from_utf8(data).map_err(From::from)
            }
            ti => unexpected_type(&ti),
        }
    }

    /// Decode a single byte string and borrow it from underlying
    /// buffer instead of allocating.
    ///
    /// Please note that indefinite byte strings are not supported by this
    /// method.
    pub fn bytes_borrow(&mut self) -> DecodeResult<&[u8]> {
        match self.typeinfo()? {
            (Type::Bytes, 31) => unexpected_type(&(Type::Bytes, 31)),
            (Type::Bytes, i) => {
                let max = self.config.max_len_bytes;
                self.kernel.raw_slice(i, max)
            }
            ti => unexpected_type(&ti),
        }
    }
}

// Iterators ////////////////////////////////////////////////////////////////

/// Iterator over the chunks of an indefinite bytes item.
pub struct BytesIter<'r, R: 'r> {
    decoder: &'r mut Decoder<R>,
}

impl<'r, R: 'r + ReadBytesExt> Iterator for BytesIter<'r, R> {
    type Item = DecodeResult<Vec<u8>>;

    fn next(&mut self) -> Option<DecodeResult<Vec<u8>>> {
        match or_break(self.decoder.bytes()) {
            Ok(None) => None,
            Ok(Some(b)) => Some(Ok(b)),
            Err(e) => Some(Err(e)),
        }
    }
}

/// Iterator over the chunks of an indefinite text item.
pub struct TextIter<'r, R: 'r> {
    decoder: &'r mut Decoder<R>,
}

impl<'r, R: 'r + ReadBytesExt> Iterator for TextIter<'r, R> {
    type Item = DecodeResult<String>;

    fn next(&mut self) -> Option<DecodeResult<String>> {
        match or_break(self.decoder.text()) {
            Ok(None) => None,
            Ok(Some(b)) => Some(Ok(b)),
            Err(e) => Some(Err(e)),
        }
    }
}

// Generic Decoder //////////////////////////////////////////////////////////

/// A generic decoder decodes arbitrary CBOR into a `Value` AST.
pub struct GenericDecoder<R> {
    decoder: Decoder<R>,
}

impl<R: ReadBytesExt> GenericDecoder<R> {
    pub fn new(c: Config, r: R) -> GenericDecoder<R> {
        GenericDecoder {
            decoder: Decoder::new(c, r),
        }
    }

    pub fn from_decoder(d: Decoder<R>) -> GenericDecoder<R> {
        GenericDecoder { decoder: d }
    }

    pub fn into_inner(self) -> Decoder<R> {
        self.decoder
    }

    #[allow(clippy::should_implement_trait)]
    pub fn borrow_mut(&mut self) -> &mut Decoder<R> {
        &mut self.decoder
    }

    /// Decode into a `Value`, i.e. an intermediate representation which
    /// can be further deconstructed using a `Cursor`.
    /// This supports indefinite decoding as well as tag validation
    /// (if not disabled).
    pub fn value(&mut self) -> DecodeResult<Value> {
        let start = self.decoder.config.max_nesting;
        self.decode_value(start)
    }

    fn decode_value(&mut self, level: usize) -> DecodeResult<Value> {
        if level == 0 {
            return Err(DecodeError::TooNested);
        }
        match self.decoder.kernel.typeinfo()? {
            ti @ (Type::UInt8, _) => self.decoder.kernel.u8(&ti).map(Value::U8),
            ti @ (Type::UInt16, _) => self.decoder.kernel.u16(&ti).map(Value::U16),
            ti @ (Type::UInt32, _) => self.decoder.kernel.u32(&ti).map(Value::U32),
            ti @ (Type::UInt64, _) => self.decoder.kernel.u64(&ti).map(Value::U64),
            ti @ (Type::Int8, _) => self.decoder.kernel.i16(&ti).map(|n| {
                if n > i8::MAX as i16 || n < i8::MIN as i16 {
                    Value::I16(n)
                } else {
                    Value::I8(n as i8)
                }
            }),
            ti @ (Type::Int16, _) => self.decoder.kernel.i32(&ti).map(|n| {
                if n > i16::MAX as i32 || n < i16::MIN as i32 {
                    Value::I32(n)
                } else {
                    Value::I16(n as i16)
                }
            }),
            ti @ (Type::Int32, _) => self.decoder.kernel.i64(&ti).map(|n| {
                if n > i32::MAX as i64 || n < i32::MIN as i64 {
                    Value::I64(n)
                } else {
                    Value::I32(n as i32)
                }
            }),
            (Type::Int64, a) => self.decoder.kernel.unsigned(a).map(|n| {
                if n > i64::MAX as u64 {
                    Value::Int(Int::Neg(n))
                } else {
                    Value::I64(-1 - n as i64)
                }
            }),
            ti @ (Type::Float16, _) => self.decoder.kernel.f16(&ti).map(Value::F32),
            ti @ (Type::Float32, _) => self.decoder.kernel.f32(&ti).map(Value::F32),
            ti @ (Type::Float64, _) => self.decoder.kernel.f64(&ti).map(Value::F64),
            ti @ (Type::Bool, _) => self.decoder.kernel.bool(&ti).map(Value::Bool),
            (Type::Null, _) => Ok(Value::Null),
            (Type::Undefined, _) => Ok(Value::Undefined),
            (Type::Break, _) => Ok(Value::Break),
            (Type::Bytes, 31) => {
                // indefinite byte string
                let mut i = 0u64;
                let mut v = LinkedList::new();
                loop {
                    match self.decoder.bytes() {
                        Ok(chunk) => {
                            i += chunk.len() as u64;
                            if i > self.decoder.config.max_len_bytes as u64 {
                                return Err(DecodeError::TooLong {
                                    max: self.decoder.config.max_len_bytes,
                                    actual: i,
                                });
                            }
                            v.push_back(chunk)
                        }
                        Err(ref e) if is_break(e) => break,
                        Err(e) => return Err(e),
                    }
                }
                Ok(Value::Bytes(Bytes::Chunks(v)))
            }
            (Type::Bytes, a) => {
                let max = self.decoder.config.max_len_bytes;
                self.decoder
                    .kernel
                    .raw_data(a, max)
                    .map(|x| Value::Bytes(Bytes::Bytes(x)))
            }
            (Type::Text, 31) => {
                // indefinite string
                let mut i = 0u64;
                let mut v = LinkedList::new();
                loop {
                    match self.decoder.text() {
                        Ok(chunk) => {
                            i += chunk.len() as u64;
                            if i > self.decoder.config.max_len_text as u64 {
                                return Err(DecodeError::TooLong {
                                    max: self.decoder.config.max_len_text,
                                    actual: i,
                                });
                            }
                            v.push_back(chunk)
                        }
                        Err(ref e) if is_break(e) => break,
                        Err(e) => return Err(e),
                    }
                }
                Ok(Value::Text(Text::Chunks(v)))
            }
            (Type::Text, a) => {
                let max = self.decoder.config.max_len_text;
                let data = self.decoder.kernel.raw_data(a, max)?;
                String::from_utf8(data)
                    .map(|x| Value::Text(Text::Text(x)))
                    .map_err(From::from)
            }
            (Type::Array, 31) => {
                // indefinite length array
                let mut i = 0u64;
                let mut v = Vec::new();
                loop {
                    i += 1;
                    if i > self.decoder.config.max_len_array as u64 {
                        return Err(DecodeError::TooLong {
                            max: self.decoder.config.max_len_array,
                            actual: i,
                        });
                    }
                    match self.decode_value(level - 1) {
                        Ok(Value::Break) => break,
                        Ok(x) => v.push(x),
                        e => return e,
                    }
                }
                Ok(Value::Array(v))
            }
            (Type::Array, a) => {
                let len = self.decoder.kernel.unsigned(a)?;
                if len > self.decoder.config.max_len_array as u64 {
                    return Err(DecodeError::TooLong {
                        max: self.decoder.config.max_len_array,
                        actual: len,
                    });
                }
                let n = len as usize;
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    v.push(self.decode_value(level - 1)?);
                }
                Ok(Value::Array(v))
            }
            (Type::Object, 31) => {
                // indefinite size object
                let mut i = 0u64;
                let mut m = BTreeMap::new();
                loop {
                    i += 1;
                    if i > self.decoder.config.max_size_map as u64 {
                        return Err(DecodeError::TooLong {
                            max: self.decoder.config.max_size_map,
                            actual: i,
                        });
                    }
                    match self.decode_key(level - 1) {
                        Ok(key) => {
                            if m.contains_key(&key) {
                                return Err(DecodeError::DuplicateKey(key));
                            }
                            match self.decode_value(level - 1)? {
                                Value::Break => return Err(DecodeError::UnexpectedBreak),
                                value => {
                                    m.insert(key, value);
                                }
                            }
                        }
                        Err(DecodeError::InvalidKey(Value::Break)) => break,
                        Err(e) => return Err(e),
                    }
                }
                Ok(Value::Map(m))
            }
            (Type::Object, a) => {
                let len = self.decoder.kernel.unsigned(a)?;
                if len > self.decoder.config.max_size_map as u64 {
                    return Err(DecodeError::TooLong {
                        max: self.decoder.config.max_size_map,
                        actual: len,
                    });
                }
                let n = len as usize;
                let mut m = BTreeMap::new();
                for _ in 0..n {
                    let key = self.decode_key(level - 1)?;
                    if m.contains_key(&key) {
                        return Err(DecodeError::DuplicateKey(key));
                    }
                    m.insert(key, self.decode_value(level - 1)?);
                }
                Ok(Value::Map(m))
            }
            (Type::Tagged, a) => {
                let tag = self.decoder.kernel.unsigned(a).map(Tag::of)?;
                if self.decoder.config.skip_tags {
                    return self.decode_value(level - 1);
                }
                let val = self
                    .decode_value(level - 1)
                    .map(|v| Value::Tagged(tag, Box::new(v)))?;
                if self.decoder.config.check_tags && !value::check(&val) {
                    return Err(DecodeError::InvalidTag(val));
                }
                Ok(val)
            }
            (Type::Unassigned { major: 7, info: a }, _) => Ok(Value::Simple(Simple::Unassigned(a))),
            (Type::Reserved { major: 7, info: a }, _) => Ok(Value::Simple(Simple::Reserved(a))),
            ti => unexpected_type(&ti),
        }
    }

    fn decode_key(&mut self, level: usize) -> DecodeResult<Key> {
        match self.decode_value(level)? {
            Value::Bool(x) => Ok(Key::Bool(x)),
            Value::Bytes(x) => Ok(Key::Bytes(x)),
            Value::Text(x) => Ok(Key::Text(x)),
            Value::I8(x) => Ok(Key::i64(x as i64)),
            Value::I16(x) => Ok(Key::i64(x as i64)),
            Value::I32(x) => Ok(Key::i64(x as i64)),
            Value::I64(x) => Ok(Key::i64(x)),
            Value::U8(x) => Ok(Key::u64(x as u64)),
            Value::U16(x) => Ok(Key::u64(x as u64)),
            Value::U32(x) => Ok(Key::u64(x as u64)),
            Value::U64(x) => Ok(Key::u64(x)),
            Value::Int(x) => Ok(Key::Int(x)),
            other => Err(DecodeError::InvalidKey(other)),
        }
    }
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tag;
    use crate::value::{self, Int, Key, Simple, Value};
    use rustc_serialize::hex::FromHex;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::{f32, f64, u64};

    #[test]
    fn unsigned() {
        assert_eq!(Some(0), decoder("00").u8().ok());
        assert_eq!(Some(1), decoder("01").u8().ok());
        assert_eq!(Some(10), decoder("0a").u8().ok());
        assert_eq!(Some(23), decoder("17").u8().ok());
        assert_eq!(Some(24), decoder("1818").u8().ok());
        assert_eq!(Some(25), decoder("1819").u8().ok());
        assert_eq!(Some(100), decoder("1864").u8().ok());
        assert_eq!(Some(1000), decoder("1903e8").u16().ok());
        assert_eq!(Some(1000000), decoder("1a000f4240").u32().ok());
        assert_eq!(
            Some(1000000000000),
            decoder("1b000000e8d4a51000").u64().ok()
        );
        assert_eq!(
            Some(18446744073709551615),
            decoder("1bffffffffffffffff").u64().ok()
        );
    }

    #[test]
    fn signed() {
        assert_eq!(Some(-1), decoder("20").i8().ok());
        assert_eq!(Some(-10), decoder("29").i8().ok());
        assert_eq!(Some(-100), decoder("3863").i8().ok());
        assert_eq!(Some(-500), decoder("3901f3").i16().ok());
        assert_eq!(Some(-1000), decoder("3903e7").i16().ok());
        assert_eq!(Some(-343434), decoder("3a00053d89").i32().ok());
        assert_eq!(Some(-23764523654), decoder("3b000000058879da85").i64().ok())
    }

    #[test]
    fn mixed() {
        assert_eq!(Some(0), decoder("00").i8().ok());
        assert_eq!(Some(1), decoder("01").i8().ok());
        assert_eq!(Some(10), decoder("0a").i8().ok());
        assert_eq!(Some(23), decoder("17").i8().ok());
        assert_eq!(Some(24), decoder("1818").i8().ok());
        assert_eq!(Some(25), decoder("1819").i8().ok());
        assert_eq!(Some(100), decoder("1864").i8().ok());
        assert_eq!(Some(1000), decoder("1903e8").i16().ok());
        assert_eq!(Some(1000000), decoder("1a000f4240").i32().ok());
    }

    #[test]
    fn int() {
        assert_eq!(Some(Some(0)), decoder("00").int().ok().map(|n| n.i64()));
        assert_eq!(Some(Some(1)), decoder("01").int().ok().map(|n| n.i64()));
        assert_eq!(Some(Some(10)), decoder("0a").int().ok().map(|n| n.i64()));
        assert_eq!(Some(Some(23)), decoder("17").int().ok().map(|n| n.i64()));
        assert_eq!(Some(Some(24)), decoder("1818").int().ok().map(|n| n.i64()));
        assert_eq!(Some(Some(25)), decoder("1819").int().ok().map(|n| n.i64()));
        assert_eq!(Some(Some(100)), decoder("1864").int().ok().map(|n| n.i64()));
        assert_eq!(
            Some(Some(1000)),
            decoder("1903e8").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(1000000)),
            decoder("1a000f4240").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(1000000000000)),
            decoder("1b000000e8d4a51000").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(None),
            decoder("1bffffffffffffffff").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(0xffffffffffffffff)),
            decoder("1bffffffffffffffff").int().ok().map(|n| n.u64())
        );
        assert_eq!(
            Some(Some(0x7fffffffffffffff)),
            decoder("1b7fffffffffffffff").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(-9223372036854775808)),
            decoder("3b7fffffffffffffff").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Int::Neg(u64::MAX)),
            decoder("3bffffffffffffffff").int().ok()
        );
        assert_eq!(Some(Some(-1)), decoder("20").int().ok().map(|n| n.i64()));
        assert_eq!(Some(Some(-10)), decoder("29").int().ok().map(|n| n.i64()));
        assert_eq!(
            Some(Some(-100)),
            decoder("3863").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(-500)),
            decoder("3901f3").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(-1000)),
            decoder("3903e7").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(-343434)),
            decoder("3a00053d89").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Some(-23764523654)),
            decoder("3b000000058879da85").int().ok().map(|n| n.i64())
        );
        assert_eq!(
            Some(Value::Int(Int::Neg(u64::MAX))),
            gen_decoder("3bffffffffffffffff").value().ok()
        )
    }

    #[test]
    fn float() {
        assert_eq!(Some(0.0), decoder("f90000").f16().ok());
        assert_eq!(Some(-0.0), decoder("f98000").f16().ok());
        assert_eq!(Some(1.0), decoder("f93c00").f16().ok());
        assert_eq!(Some(1.5), decoder("f93e00").f16().ok());
        assert_eq!(Some(65504.0), decoder("f97bff").f16().ok());
        assert_eq!(Some(f32::INFINITY), decoder("f97c00").f16().ok());
        assert_eq!(Some(-f32::INFINITY), decoder("f9fc00").f16().ok());
        assert!(decoder("f97e00").f16().ok().unwrap().is_nan());

        assert_eq!(Some(100000.0), decoder("fa47c35000").f32().ok());
        assert_eq!(Some(3.402_823_5e38), decoder("fa7f7fffff").f32().ok());
        assert_eq!(Some(-4.1), decoder("fbc010666666666666").f64().ok());

        assert_eq!(Some(f32::INFINITY), decoder("fa7f800000").f32().ok());
        assert_eq!(Some(-f32::INFINITY), decoder("faff800000").f32().ok());
        assert!(decoder("fa7fc00000").f32().ok().unwrap().is_nan());

        assert_eq!(Some(1.0e+300), decoder("fb7e37e43c8800759c").f64().ok());
        assert_eq!(
            Some(f64::INFINITY),
            decoder("fb7ff0000000000000").f64().ok()
        );
        assert_eq!(
            Some(-f64::INFINITY),
            decoder("fbfff0000000000000").f64().ok()
        );
        assert!(decoder("fb7ff8000000000000").f64().ok().unwrap().is_nan())
    }

    #[test]
    fn bool() {
        assert_eq!(Some(false), decoder("f4").bool().ok());
        assert_eq!(Some(true), decoder("f5").bool().ok());
    }

    #[test]
    fn simple() {
        assert_eq!(Some(Simple::Unassigned(16)), decoder("f0").simple().ok());
        assert_eq!(Some(Simple::Reserved(24)), decoder("f818").simple().ok());
        assert_eq!(Some(Simple::Unassigned(255)), decoder("f8ff").simple().ok())
    }

    #[test]
    fn bytes() {
        assert_eq!(Some(vec![1, 2, 3, 4]), decoder("4401020304").bytes().ok())
    }

    #[test]
    fn read_bytes() {
        let mut buf = [0u8; 4];
        assert_eq!(Some(4), decoder("4401020304").read_bytes(&mut buf).ok());
        assert_eq!([1, 2, 3, 4], buf)
    }

    #[test]
    fn text() {
        let expected1 = String::from("dfsdfsdf\r\nsdf\r\nhello\r\nsdfsfsdfs");
        assert_eq!(
            Some(expected1),
            decoder("781f64667364667364660d0a7364660d0a68656c6c6f0d0a736466736673646673")
                .text()
                .ok()
        );

        let expected2 = String::from("\u{00fc}");
        assert_eq!(Some(expected2), decoder("62c3bc").text().ok());

        let mut r = Vec::new();
        let mut d = decoder("7f657374726561646d696e67ff");
        for t in d.text_iter().unwrap() {
            r.push(t.unwrap())
        }
        assert_eq!(vec![String::from("strea"), String::from("ming")], r);
    }

    #[test]
    fn text_borrow() {
        let expected1 = "dfsdfsdf\r\nsdf\r\nhello\r\nsdfsfsdfs";
        assert_eq!(
            Some(expected1),
            decoder("781f64667364667364660d0a7364660d0a68656c6c6f0d0a736466736673646673")
                .text_borrow()
                .ok()
        );
    }

    #[test]
    fn bytes_borrow() {
        let expected1 = &b"dfsdfsdf\r\nsdf\r\nhello\r\nsdfsfsdfs"[..];
        assert_eq!(
            Some(expected1),
            decoder("581f64667364667364660d0a7364660d0a68656c6c6f0d0a736466736673646673")
                .bytes_borrow()
                .ok()
        );
    }

    #[test]
    fn option() {
        let none: Option<u8> = None;
        let some: Option<u8> = Some(1);
        assert_eq!(Some(none), opt(decoder("f6").u8()).ok());
        assert_eq!(Some(some), opt(decoder("01").u8()).ok())
    }

    #[test]
    fn undefined() {
        let undef: Option<u8> = None;
        let def: Option<u8> = Some(1);
        assert_eq!(Some(undef), maybe(decoder("f7").u8()).ok());
        assert_eq!(Some(def), maybe(decoder("01").u8()).ok())
    }

    #[test]
    fn empty_arrays() {
        assert_eq!(Some(Value::Array(vec![])), gen_decoder("9fff").value().ok());

        let mut d = decoder("9fff");
        d.array_begin().unwrap();
        or_break(d.u8()).unwrap();
    }

    #[test]
    fn array() {
        let mut d = decoder("83010203");
        assert_eq!(3, d.array().unwrap());
        assert_eq!(Some(1u32), d.u32().ok());
        assert_eq!(Some(2u32), d.u32().ok());
        assert_eq!(Some(3u32), d.u32().ok());
    }

    #[test]
    fn object() {
        let mut map = BTreeMap::new();
        map.insert(String::from("a"), 1u8);
        map.insert(String::from("b"), 2u8);
        map.insert(String::from("c"), 3u8);
        let mut d = decoder("a3616101616202616303");
        let mut x = BTreeMap::new();
        for _ in 0..d.object().unwrap() {
            x.insert(d.text().unwrap(), d.u8().unwrap());
        }
        assert_eq!(map, x);
    }

    #[test]
    fn skip() {
        let mut d = decoder("a66161016162820203616382040561647f657374726561646d696e67ff61659f070405ff61666568656c6c6f");
        for _ in 0..d.object().unwrap() {
            match d.text().unwrap().as_ref() {
                "a" => {
                    d.u8().unwrap();
                }
                "b" => {
                    for _ in 0..d.array().unwrap() {
                        d.u8().unwrap();
                    }
                }
                "c" => d.skip().unwrap(),
                "d" => d.skip().unwrap(),
                "e" => d.skip().unwrap(),
                "f" => d.skip().unwrap(),
                key => panic!("unexpected key: {}", key),
            }
        }
    }

    #[test]
    fn array_of_array() {
        let mut d = decoder("828301020383010203");
        let outer = d.array().unwrap();
        let mut v = Vec::with_capacity(outer);
        for _ in 0..outer {
            let inner = d.array().unwrap();
            let mut w = Vec::with_capacity(inner);
            for _ in 0..inner {
                w.push(d.u8().unwrap())
            }
            v.push(w)
        }
        assert_eq!(vec![vec![1, 2, 3], vec![1, 2, 3]], v)
    }

    #[test]
    fn object_value() {
        let v = gen_decoder("a2616101028103").value().ok().unwrap();
        let d = value::Cursor::new(&v);
        assert_eq!(Some(1), d.field("a").u8());
        assert_eq!(Some(3), d.get(Key::u64(2)).at(0).u8())
    }

    #[test]
    fn tagged() {
        // by default, tags are ignored
        assert_eq!(Some(1363896240), decoder("c11a514b67b0").u32().ok());
        // but can be extracted if desired
        let mut d = decoder("c11a514b67b0");
        assert_eq!(Some(Tag::Timestamp), d.tag().ok());
        assert_eq!(Some(1363896240), d.u32().ok())
    }

    #[test]
    fn tagged_value() {
        match gen_decoder("c11a514b67b0").value().ok() {
            Some(Value::Tagged(Tag::Timestamp, ref v)) if **v == Value::U32(1363896240) => (),
            other => panic!("impossible tagged value: {:?}", other),
        }
        match gen_decoder("c1fb41d452d9ec200000").value().ok() {
            Some(Value::Tagged(Tag::Timestamp, ref v)) if **v == Value::F64(1363896240.5) => (),
            other => panic!("impossible tagged value: {:?}", other),
        }
    }

    fn decoder(s: &str) -> Decoder<Cursor<Vec<u8>>> {
        Decoder::new(Config::default(), Cursor::new(s.from_hex().unwrap()))
    }

    fn gen_decoder(s: &str) -> GenericDecoder<Cursor<Vec<u8>>> {
        GenericDecoder::from_decoder(decoder(s))
    }
}
