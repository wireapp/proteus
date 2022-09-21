pub type RawPreKeyId = u16;
pub type RawPreKey = Vec<u8>;

pub trait PreKeyStore {
    type Error;

    /// Lookup prekey by ID.
    fn prekey(&mut self, id: RawPreKeyId) -> Result<Option<RawPreKey>, Self::Error>;

    /// Remove prekey by ID.
    fn remove(&mut self, id: RawPreKeyId) -> Result<(), Self::Error>;
}
