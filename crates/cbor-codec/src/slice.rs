// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

//! `ReadSlice` trait to allow efficient reading of slices without copying.

use std::error::Error;
use std::fmt;
use std::io::{self, Cursor};

/// Type which supports reading a slice of bytes.
pub trait ReadSlice {
    fn read_slice(&mut self, n: usize) -> Result<&[u8], ReadSliceError>;
}

impl ReadSlice for Cursor<Vec<u8>> {
    fn read_slice(&mut self, n: usize) -> Result<&[u8], ReadSliceError> {
        let start = self.position() as usize;
        if self.get_ref().len() - start < n {
            return Err(ReadSliceError::InsufficientData);
        }
        self.set_position((start + n) as u64);
        Ok(&self.get_ref()[start..start + n])
    }
}

impl<'r> ReadSlice for Cursor<&'r [u8]> {
    fn read_slice(&mut self, n: usize) -> Result<&[u8], ReadSliceError> {
        let start = self.position() as usize;
        if self.get_ref().len() - start < n {
            return Err(ReadSliceError::InsufficientData);
        }
        self.set_position((start + n) as u64);
        Ok(&self.get_ref()[start..start + n])
    }
}

#[derive(Debug)]
pub enum ReadSliceError {
    IoError(io::Error),
    InsufficientData,
}

impl fmt::Display for ReadSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            ReadSliceError::IoError(ref e) => write!(f, "ReadSliceError: I/O error: {}", *e),
            ReadSliceError::InsufficientData => {
                write!(f, "ReadSliceError: not enough data available")
            }
        }
    }
}

impl Error for ReadSliceError {
    fn description(&self) -> &str {
        "ReadSliceError"
    }

    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            ReadSliceError::IoError(ref e) => Some(e),
            _ => None,
        }
    }
}
