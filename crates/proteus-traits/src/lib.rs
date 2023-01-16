// Copyright (C) 2022 Wire Swiss GmbH <support@wire.com>
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

pub type RawPreKeyId = u16;
pub type RawPreKey = Vec<u8>;

pub trait ProteusErrorCode {
    fn code(&self) -> ProteusErrorKind;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ProteusErrorKind {
    None = 0,
    Unknown = u16::MAX,
    // Proteus Errors
    DefaultProteusError = 1,
    AssertZeroArray = 100,
    PreKeyNotFound = 101,
    SessionStateNotFoundForTag = 102,
    MessageKeysAboveMessageChainCounterGap = 103,
    SkippedMessageKeysAboveMessageChainCounterGap = 104,
    // Decryption errors
    UnknownDecryptionError = 2,
    UnknownMessageType = 200,
    CannotInitialiseSessionFromCipherMessage = 201,
    UnknownMessageFormat = 202,
    CouldntDeletePreKey = 203,
    RemoteIdentityChanged = 204,
    NoMatchingSessionTag = 205,
    MessageInSyncDecryptionFailed = 206,
    SessionBrokenOrOutOfSync = 207,
    OutdatedMessage = 208,
    DuplicateMessage = 209,
    OlderMessageVerificationFailed = 210,
    TooDistantFutureRecvChainBeginning = 211,
    TooDistantFuture = 212,
    SenderFailedEncryption = 213,
    // Decode errors
    DecodeError = 3,
    LocalIdentityChanged = 300,
    MalformedMessageData = 301,
    UnrecognisedMessageType = 302,
    InvalidArrayLen = 303,
    // Encryption errors
    InvalidInput = 4,
    CipherMessageDoesntMatchSignature = 405,
    PreKeyMessageDoesntMatchSignature = 406,
    RootKeyDoesntMatchSignature = 407,
    // System errors
    OtherSystemError = 5,
    IoError = 501,
    Ed25519Error = 502,
    InvalidKdfOutputLength = 504,
    IntegerOverflow = 505,
}

impl ProteusErrorKind {
    pub fn is_error(&self) -> bool {
        *self == Self::None
    }
}

#[async_trait::async_trait(?Send)]
pub trait PreKeyStore {
    type Error: ProteusErrorCode;

    /// Lookup prekey by ID.
    async fn prekey(&mut self, id: RawPreKeyId) -> Result<Option<RawPreKey>, Self::Error>;

    /// Remove prekey by ID.
    async fn remove(&mut self, id: RawPreKeyId) -> Result<(), Self::Error>;
}
