// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

#![feature(slice_bytes)]

extern crate cbor;
extern crate byteorder;
extern crate hkdf;
extern crate libc;
extern crate sodiumoxide;

mod internal;

pub mod keys;
pub mod session;
pub mod message;

pub fn init() {
    sodiumoxide::init();
}

pub use internal::util::{DecodeError, EncodeError};
