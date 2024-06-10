use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid plaintext length")]
    InvalidPlaintextLength,

    #[error("Invalid cipher text length")]
    InvalidCipherTextLength,

    #[error("Invalid bytes. Can't convert to a word.")]
    InvalidBytes,

    #[error("Provided key is not valid")]
    InvalidKey,

    #[error("Key size is invalid")]
    InvalidKeySize,

    #[error("Word size is invalid")]
    InvalidWordSize,

    #[error("Invalid number of rounds")]
    InvalidRoundsCount,

    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
}
