// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use bincode::SizeLimit;
use bincode::{DecoderReader, DecodingError, EncoderWriter, EncodingError};
use rustc_serialize::{Decodable, Decoder};
use std::io::BufRead;
use std::vec::Vec;

pub fn encode<A, F>(a: &A, f: F) -> Result<Vec<u8>, EncodingError>
where F: Fn(&A, &mut EncoderWriter<Vec<u8>>) -> Result<(), EncodingError>
{
    let mut w = Vec::new();
    {
        let mut e = EncoderWriter::new(&mut w);
        try!(f(a, &mut e));
    }
    Ok(w)
}

pub fn decode<'r, A, F>(b: &'r [u8], f: F) -> Result<A, DecodingError>
where F: Fn(&mut DecoderReader<&'r [u8]>) -> Result<A, DecodingError>
{
    let mut b = b;
    let mut d = DecoderReader::new(&mut b, SizeLimit::Infinite);
    f(&mut d)
}

// Array32 //////////////////////////////////////////////////////////////////

pub struct Array32 { pub array: [u8; 32] }

impl Array32 {
    pub fn decode<R: BufRead>(d: &mut DecoderReader<R>) -> Result<Array32, DecodingError> {
        if 32_u64 != try!(Decodable::decode(d)) {
            return Err(d.error("array length =/= 32"))
        }
        let mut a = [0u8; 32];
        for i in 0 .. 32 {
            a[i] = try!(Decodable::decode(d))
        }
        Ok(Array32 { array: a })
    }
}

// Array64 //////////////////////////////////////////////////////////////////

pub struct Array64 { pub array: [u8; 64] }

impl Array64 {
    pub fn decode<R: BufRead>(d: &mut DecoderReader<R>) -> Result<Array64, DecodingError> {
        if 64_u64 != try!(Decodable::decode(d)) {
            return Err(d.error("array length =/= 64"))
        }
        let mut a = [0u8; 64];
        for i in 0 .. 64 {
            a[i] = try!(Decodable::decode(d))
        }
        Ok(Array64 { array: a })
    }
}
