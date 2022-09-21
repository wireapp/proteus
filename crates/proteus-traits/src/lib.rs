pub type RawPreKeyId = u16;
pub type RawPreKey = Vec<u8>;

#[async_trait::async_trait(?Send)]
pub trait PreKeyStore {
    type Error;

    /// Lookup prekey by ID.
    async fn prekey(&mut self, id: RawPreKeyId) -> Result<Option<RawPreKey>, Self::Error>;

    /// Remove prekey by ID.
    async fn remove(&mut self, id: RawPreKeyId) -> Result<(), Self::Error>;
}
