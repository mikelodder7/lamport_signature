/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use thiserror::Error;

/// Errors in sign-verify scheme.
#[derive(Error, Debug)]
pub enum LamportError {
    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// Private key was reused.
    #[error("Private key was reused.")]
    PrivateKeyReuseError,
    /// Invalid private key bytes.
    #[error("Invalid private key bytes.")]
    InvalidPrivateKeyBytes,
    /// Invalid signature bytes.
    #[error("Invalid signature bytes.")]
    InvalidSignatureBytes,
}

/// Result type for Lamport errors.
pub type LamportResult<T> = Result<T, LamportError>;
