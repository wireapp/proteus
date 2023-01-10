use proteus_traits::{ProteusErrorCode, ProteusErrorKind};

#[derive(Debug, thiserror::Error)]
pub enum ProteusError {
    #[error(transparent)]
    DecodeError(#[from] crate::internal::types::DecodeError),
    #[error(transparent)]
    EncodeError(#[from] crate::internal::types::EncodeError),
    #[error("The provided public key is made up of zeros!")]
    Zero,
    #[error(transparent)]
    Ed25519Error(#[from] ed25519_compact::Error),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

impl PartialEq for ProteusError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ProteusError::DecodeError(_), ProteusError::DecodeError(_)) => true,
            (ProteusError::EncodeError(_), ProteusError::EncodeError(_)) => true,
            (ProteusError::Zero, ProteusError::Zero) => true,
            (ProteusError::Ed25519Error(a), ProteusError::Ed25519Error(b)) if a == b => true,
            (ProteusError::Other(a), ProteusError::Other(b)) if a.to_string() == b.to_string() => {
                true
            }
            _ => false,
        }
    }
}

impl ProteusErrorCode for ProteusError {
    fn code(&self) -> ProteusErrorKind {
        match self {
            Self::EncodeError(e) => e.code(),
            Self::DecodeError(e) => e.code(),
            Self::Zero => ProteusErrorKind::AssertZeroArray,
            Self::Ed25519Error(_) => ProteusErrorKind::Ed25519Error,
            Self::Other(_) => ProteusErrorKind::Unknown,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub struct ProteusErrorWithCode<E: ProteusErrorCode + std::error::Error> {
    source: E,
    code: ProteusErrorKind,
}

impl<E: ProteusErrorCode + std::error::Error> ProteusErrorCode for ProteusErrorWithCode<E> {
    fn code(&self) -> ProteusErrorKind {
        self.code
    }
}

impl<E: ProteusErrorCode + std::error::Error> From<E> for ProteusErrorWithCode<E> {
    fn from(source: E) -> Self {
        Self {
            code: source.code(),
            source,
        }
    }
}

impl<E: ProteusErrorCode + std::error::Error> ProteusErrorWithCode<E> {
    pub fn with_code(mut self, code: ProteusErrorKind) -> Self {
        self.code = code;
        self
    }
}

pub type ProteusResult<T> = Result<T, ProteusError>;
