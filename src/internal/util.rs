// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
// Based on libsignal-protocol-java by Open Whisper Systems
// https://github.com/WhisperSystems/libsignal-protocol-java.
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

// Hex formatting ///////////////////////////////////////////////////////////

struct HexSlice<'a>(&'a [u8]);
impl<'a> HexSlice<'a> {
    fn new<T: ?Sized + AsRef<[u8]> + 'a>(data: &'a T) -> Self {
        Self(data.as_ref())
    }
}

impl std::fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{:x}", b)?;
        }
        Ok(())
    }
}

pub fn fmt_hex(xs: &[u8]) -> String {
    format!("{}", HexSlice::new(xs))
}

// Test support /////////////////////////////////////////////////////////////
#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
pub fn roundtrip<F, G, A>(enc: F, dec: G) -> A
where
    F: Fn(&mut Cursor<Vec<u8>>) -> crate::internal::types::EncodeResult<()>,
    G: Fn(&mut Cursor<Vec<u8>>) -> crate::internal::types::DecodeResult<A>,
{
    let mut rw = Cursor::new(Vec::new());
    enc(&mut rw).unwrap();
    dec(&mut rw).unwrap()
}
