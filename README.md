# SD-JWT Rust Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Rust.
Supported version: 7.

Note: while the project is started as a reference implementation, it is intended to be evolved to a production-ready, high-performance implementations in the long-run.

## API
Note: the current version of the crate is 0.0.x, so the API should be considered as experimental.
Proposals about API improvements are highly appreciated.

```rust
fn demo() {
    let issuer_crypto_provider = Box::new(SDJWTCryptoProviderBuiltin::new().with_signing_key(issuer_private_key, "ES256"));
    let mut issuer = SDJWTIssuer::new(issuer_crypto_provider);
    let sd_jwt = issuer.issue_sd_jwt(claims, ClaimsForSelectiveDisclosureStrategy::AllLevels, holder_jwk, add_decoy, SDJWTSerializationFormat::Compact).unwrap();

    let holder_crypto_provider = Box::new(SDJWTCryptoProviderBuiltin::new().with_verifying_key(issuer_public_key, "ES256"));
    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact, holder_crypto_provider).unwrap();
    let presentation = holder.create_presentation(claims_to_disclosure, None, None).unwrap();

    let verifier_crypto_provider = Box::new(SDJWTCryptoProviderBuiltin::new().with_verifying_key(issuer_public_key, "ES256"));
    let verified_claims = SDJWTVerifier::new(presentation, verifier_crypto_provider, None, None, SDJWTSerializationFormat::Compact).unwrap()
                            .verified_claims;
}
```

See `tests/demos.rs` for more details;

### Custom crypto providers

`SDJWTCryptoProviderBuiltin` covers the common case where raw key material is
held in memory. To keep keys in a platform keystore, HSM, or remote KMS —
where keys are non-extractable and only the signing/verification *operation*
may cross the boundary — implement `SDJWTCryptoProvider` and inject that
instead:

```rust
struct KeystoreProvider { /* handle to the keystore */ }

impl SDJWTCryptoProvider for KeystoreProvider {
    fn signing_alg(&self, role: SignatureRole) -> Result<String> {
        // JWS `alg` name of the key the keystore holds for `role`.
    }
    fn allowed_verifying_algs(&self, role: SignatureRole) -> Result<Vec<String>> {
        // Algorithm allowlist (RFC 8725 §3.1): the library rejects any JWT
        // whose header `alg` is not listed here BEFORE calling `verify`.
    }
    fn sign(&self, message: &[u8], role: SignatureRole) -> Result<Vec<u8>> {
        // Sign the raw JWS signing input with the keystore-held key.
    }
    fn verify(&self, message: &[u8], signature: &[u8], request: &KeyRequest) -> Result<()> {
        // Select and trust a key for the signer `request` describes.
        // `request.iss` / `request.kid` / `request.x5c` are UNVERIFIED input.
    }
}
```

The library keeps ownership of all JWS encoding/decoding, header parsing
(rejecting `alg` `none` and symmetric `HS*`), `exp`/`nbf` validation, and
enforcing the provider's algorithm allowlist; the provider owns key
selection and trust.

## Repository structure

### SD-JWT Rust crate
SD-JWT crate is the root of the repository.

To build the project simply perform:
```shell
cargo build
```

To run tests:
```shell
cargo test
```

### Interoperability testing tool
See [Generate tool README](./generate/README.md) document.

## External Dependencies

Dual license (MIT/Apache 2.0) dependencies: [base64](https://crates.io/crates/base64), [lazy_static](https://crates.io/crates/lazy_static) [log](https://crates.io/crates/log), [serde](https://crates.io/crates/serde), [serde_json](https://crates.io/crates/serde_json), [sha2](https://crates.io/crates/sha2), [rand](https://crates.io/crates/rand), [hmac](https://crates.io/crates/hmac), [thiserror](https://crates.io/crates/thiserror).
MIT license dependencies: [jsonwebtoken](https://crates.io/crates/jsonwebtoken), [strum](https://crates.io/crates/strum)

Note: the list of dependencies may be changed in the future.

## Initial Maintainers

- Sergey Minaev ([Github](https://github.com/jovfer))
- DSR Corporation Decentralized Systems Team ([Github](https://github.com/orgs/DSRCorporation/teams/decentralized-systems))
