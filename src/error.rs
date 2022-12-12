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

pub type ProteusResult<T> = Result<T, ProteusError>;
