// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use libc::c_int;

extern {
    pub fn crypto_sign_ed25519_pk_to_curve25519(c: *mut u8, e: *const u8) -> c_int;
    pub fn crypto_sign_ed25519_sk_to_curve25519(c: *mut u8, e: *const u8) -> c_int;
}
