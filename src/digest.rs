// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{Error, Result};

/// Hash algorithm for SD-JWT disclosures, decoys, and Key Binding `sd_hash`.
/// Independent of the JWS signature algorithm. RFC 9901 defaults to SHA-256.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SDJWTDigestAlgorithm {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl SDJWTDigestAlgorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        }
    }

    pub(crate) fn from_name(name: &str) -> Result<Self> {
        match name {
            "sha-256" => Ok(Self::Sha256),
            "sha-384" => Ok(Self::Sha384),
            "sha-512" => Ok(Self::Sha512),
            _ => Err(Error::InvalidInput(format!(
                "Unsupported SD-JWT hash algorithm: {name}"
            ))),
        }
    }

    pub(crate) fn base64_hash(self, data: &[u8]) -> String {
        match self {
            Self::Sha256 => URL_SAFE_NO_PAD.encode(Sha256::digest(data)),
            Self::Sha384 => URL_SAFE_NO_PAD.encode(Sha384::digest(data)),
            Self::Sha512 => URL_SAFE_NO_PAD.encode(Sha512::digest(data)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SDJWTDigestAlgorithm;

    #[test]
    fn parse_case_sensitive_digest_algorithm_names() {
        for algorithm in [
            SDJWTDigestAlgorithm::Sha256,
            SDJWTDigestAlgorithm::Sha384,
            SDJWTDigestAlgorithm::Sha512,
        ] {
            assert_eq!(
                SDJWTDigestAlgorithm::from_name(algorithm.name()).unwrap(),
                algorithm
            );
        }
        assert_eq!(
            SDJWTDigestAlgorithm::default(),
            SDJWTDigestAlgorithm::Sha256
        );
        assert!(SDJWTDigestAlgorithm::from_name("SHA-256").is_err());
        assert!(SDJWTDigestAlgorithm::from_name("sha-1").is_err());
    }

    #[test]
    fn hash_digest_algorithm_vectors() {
        assert_eq!(
            SDJWTDigestAlgorithm::Sha256.base64_hash(b"abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
        assert_eq!(
            SDJWTDigestAlgorithm::Sha384.base64_hash(b"abc"),
            "ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP_W-2AhgcroefMI1i67KE0yCWn"
        );
        assert_eq!(
            SDJWTDigestAlgorithm::Sha512.base64_hash(b"abc"),
            "3a81oZNherrMQXNJriBBMRLm-k6JqX6iCp7u5ktV05ohkpkqJ0_BqDa6PCOj_uu9RU1EI2Q86A4qmslPpUyknw"
        );
    }
}
