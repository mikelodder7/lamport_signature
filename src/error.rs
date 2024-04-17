/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use thiserror::Error;

/// Errors in lamport signing scheme.
#[derive(Error, Debug)]
pub enum LamportError {
    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// Vsss error.
    #[error("Vsss error: {0}")]
    VsssError(vsss_rs::Error),
    /// Private key was reused.
    #[error("Private key was reused.")]
    PrivateKeyReuseError,
    /// Invalid private key bytes.
    #[error("Invalid private key bytes.")]
    InvalidPrivateKeyBytes,
    /// Invalid signature bytes.
    #[error("Invalid signature bytes.")]
    InvalidSignatureBytes,
    /// General Purpose errors
    #[error("General error: {0}")]
    General(String),
}

impl From<vsss_rs::Error> for LamportError {
    fn from(err: vsss_rs::Error) -> Self {
        LamportError::VsssError(err)
    }
}

impl From<&vsss_rs::Error> for LamportError {
    fn from(err: &vsss_rs::Error) -> Self {
        LamportError::VsssError(*err)
    }
}

/// Result type for Lamport errors.
pub type LamportResult<T> = Result<T, LamportError>;
