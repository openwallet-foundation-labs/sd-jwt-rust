// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

pub type Result<T> = ::core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("conversion error: Cannot convert to {0}")]
    ConversionError(String),

    #[error("invalid input: {0}")]
    DeserializationError(String),

    #[error("data field is not expected: {0}")]
    DataFieldMismatch(String),

    #[error("Digest {0} appears multiple times")]
    DuplicateDigestError(String),

    #[error("Key {0} appears multiple times")]
    DuplicateKeyError(String),

    #[error("invalid disclosure: {0}")]
    InvalidDisclosure(String),

    #[error("invalid array disclosure: {0}")]
    InvalidArrayDisclosureObject(String),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("index {idx} is out of bounds for the provided array with length {length}: {msg}")]
    IndexOutOfBounds {
        idx: usize,
        length: usize,
        msg: String,
    },

    #[error("invalid state: {0}")]
    InvalidState(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("{0}")]
    Unspecified(String),
}
