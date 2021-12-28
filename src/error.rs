#[derive(Debug, thiserror::Error)]
pub enum ProteusError {
    #[error(transparent)]
    DecodeError(#[from] crate::internal::types::DecodeError),
    #[error(transparent)]
    EncodeError(#[from] crate::internal::types::EncodeError),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type ProteusResult<T> = Result<T, ProteusError>;
