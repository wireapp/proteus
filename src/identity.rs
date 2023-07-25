// Copyright (C) 2022 Wire Swiss GmbH <support@wire.com>
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

use crate::keys::{IdentityKey, IdentityKeyPair};
use crate::{DecodeError, EncodeError};
use cbor::skip::Skip;
use cbor::{Config, Decoder, Encoder};
use std::borrow::Cow;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IdentityMode {
    Complete,
    Public,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Identity<'r> {
    Sec(Cow<'r, IdentityKeyPair>),
    Pub(Cow<'r, IdentityKey>),
}

impl<'r> Identity<'r> {
    pub fn serialise(&self) -> Result<Vec<u8>, EncodeError> {
        let mut e = Encoder::new(io::Cursor::new(Vec::new()));
        self.encode(&mut e)?;
        Ok(e.into_writer().into_inner())
    }

    pub fn deserialise<'s>(b: &[u8]) -> Result<Identity<'s>, DecodeError> {
        Identity::decode(&mut Decoder::new(Config::default(), io::Cursor::new(b)))
    }

    fn encode<W: io::Write>(&self, e: &mut Encoder<W>) -> Result<(), EncodeError> {
        match *self {
            Identity::Sec(ref id) => {
                e.u8(1)?;
                e.object(1)?;
                e.u8(0)?;
                id.encode(e)
            }
            Identity::Pub(ref id) => {
                e.u8(2)?;
                e.object(1)?;
                e.u8(0)?;
                id.encode(e)
            }
        }
    }

    fn decode<'s, R: io::Read + Skip>(d: &mut Decoder<R>) -> Result<Identity<'s>, DecodeError> {
        match d.u8()? {
            1 => {
                let n = d.object()?;
                let mut keypair = None;
                for _ in 0..n {
                    match d.u8()? {
                        0 => {
                            if keypair.is_some() {
                                return Err(DecodeError::DuplicateField("identity keypair"));
                            } else {
                                keypair =
                                    Some(Identity::Sec(Cow::Owned(IdentityKeyPair::decode(d)?)))
                            }
                        }
                        _ => d.skip()?,
                    }
                }
                keypair.ok_or(DecodeError::MissingField("identity keypair"))
            }
            2 => {
                let n = d.object()?;
                let mut key = None;
                for _ in 0..n {
                    match d.u8()? {
                        0 => {
                            if key.is_some() {
                                return Err(DecodeError::DuplicateField("identity key"));
                            } else {
                                key = Some(Identity::Pub(Cow::Owned(IdentityKey::decode(d)?)))
                            }
                        }
                        _ => d.skip()?,
                    }
                }
                key.ok_or(DecodeError::MissingField("identity key"))
            }
            t => Err(DecodeError::InvalidType(t, "unknown identity type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::util::roundtrip;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[test]
    #[wasm_bindgen_test]
    fn enc_dec_identity_sec() {
        let k = IdentityKeyPair::new();
        let identity = Identity::Sec(std::borrow::Cow::Owned(k));
        let r = roundtrip(
            |mut e| identity.encode(&mut e),
            |mut d| Identity::decode(&mut d),
        );
        assert_eq!(identity, r);
    }

    #[test]
    #[wasm_bindgen_test]
    fn enc_dec_identity_pub() {
        let k = IdentityKeyPair::new();
        let identity = Identity::Pub(std::borrow::Cow::Owned(k.public_key));
        let r = roundtrip(
            |mut e| identity.encode(&mut e),
            |mut d| Identity::decode(&mut d),
        );
        assert_eq!(identity, r);
    }
}
