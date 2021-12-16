#[derive(Debug, thiserror::Error)]
pub enum ProteusError {

    #[error(transparent)]
    Other(#[from] eyre::Report)
}

pub type ProteusResult<T> = Result<T, ProteusError>;
