// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

#![feature(collections, core, old_io, io, libc)]

extern crate bincode;
extern crate hkdf;
extern crate libc;
extern crate sodiumoxide;
extern crate "rustc-serialize" as rustc_serialize;

mod internal;

pub mod keys;
pub mod session;
pub mod message;

pub fn init() {
    sodiumoxide::init();
}

pub use internal::util::DecodeError;
pub use internal::session::binary::DecodeSessionError;
