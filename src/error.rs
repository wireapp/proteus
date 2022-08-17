#[derive(Debug, thiserror::Error)]
pub enum ProteusError {
    #[error(transparent)]
    DecodeError(#[from] crate::internal::types::DecodeError),
    #[error(transparent)]
    EncodeError(#[from] crate::internal::types::EncodeError),
}

pub type ProteusResult<T> = Result<T, ProteusError>;
