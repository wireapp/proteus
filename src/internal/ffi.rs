// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

use libc::c_int;

extern {
    pub fn crypto_sign_ed25519_pk_to_curve25519(c: *mut u8, e: *const u8) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_curve25519(c: *mut u8, e: *const u8) -> c_int;
}
