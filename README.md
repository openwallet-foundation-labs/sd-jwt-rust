# SD-JWT Rust Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Rust.
Supported version: 7.

Note: while the project is started as a reference implementation, it is intended to be evolved to a production-ready, high-performance implementations in the long-run.

## API
Note: the current version of the crate is 0.0.x, so the API should be considered as experimental.
Proposals about API improvements are highly appreciated.

```rust
fn demo() {
    let issuer_crypto_provider = Box::new(SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
        .with_issuer_signing_key(SDJWTKeyWithAlg::new(issuer_private_key, "ES256")).unwrap());
    let mut issuer = SDJWTIssuer::new(issuer_crypto_provider);
    let sd_jwt = issuer.issue_sd_jwt(claims, ClaimsForSelectiveDisclosureStrategy::AllLevels, holder_jwk, add_decoy, SDJWTSerializationFormat::Compact).unwrap();

    let holder_crypto_provider = Box::new(SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
        .with_issuer_verifying_key(SDJWTKeyWithAlg::new(issuer_public_key.clone(), "ES256")).unwrap());
    let mut holder = SDJWTHolder::new(holder_crypto_provider, sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let presentation = holder.create_presentation(claims_to_disclosure, None, None).unwrap();

    let verifier_crypto_provider = Box::new(SDJWTCryptoProviderBuiltin::new(&["ES256"], None)
        .with_issuer_verifying_key(SDJWTKeyWithAlg::new(issuer_public_key, "ES256")).unwrap());
    let verified_claims = SDJWTVerifier::new(verifier_crypto_provider, presentation, None, None, SDJWTSerializationFormat::Compact).unwrap()
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
    fn signing_alg(&self, role: SDJWTSignatureRole) -> Result<String> {
        // JWS `alg` name of the key the keystore holds for `role`.
    }
    fn allowed_verifying_algs(&self, role: SDJWTSignatureRole) -> Result<Vec<String>> {
        // Algorithm allowlist (RFC 8725 §3.1): the library rejects any JWT
        // whose header `alg` is not listed here BEFORE calling `verify`.
    }
    fn sign(&self, message: &[u8], role: SDJWTSignatureRole) -> Result<Vec<u8>> {
        // Sign the raw JWS signing input with the keystore-held key.
    }
    fn verify(&self, message: &[u8], signature: &[u8], request: &SDJWTKeyRequest) -> Result<()> {
        // Select and trust a key for the signer `request` describes.
        // `request.iss` / `request.kid` / `request.x5c` are UNVERIFIED input.
    }
}
```

Each method pair — signing (`signing_alg` + `sign`) and verifying
(`allowed_verifying_algs` + `verify`) — has a fail-closed default returning
an error, so implement only the pair(s) your party performs: signing for an
Issuer, verifying for a Verifier, both for a Holder that presents with Key
Binding.

The library keeps ownership of all JWS encoding/decoding, header parsing
(rejecting `alg` `none` and symmetric `HS*`), `exp`/`nbf` validation, and
enforcing the provider's algorithm allowlist; the provider owns key
selection and trust.

The builtin binds the Issuer verifying key to exactly one JWS algorithm
(RFC 8725 §3.1: each key is used with exactly one algorithm) — a JWT whose
header `alg` differs from the bound one is rejected before any cryptographic
operation, and the bound algorithm, never the header's, is what the crypto
layer runs. The algorithm policy is declared once, at construction:
`SDJWTCryptoProviderBuiltin::new(issuer_algs, holder_algs)` takes the
Issuer allowlist and, optionally, the Key Binding one (the KB `cnf` key
arrives in-band per presentation, so that declared set is the only KB
narrowing; pass `None` when Key Binding is not used). The key setters take
a `SDJWTKeyWithAlg` — a key bundled with the one JWS algorithm it is used with —
and return `Result`, rejecting at configuration time a key whose algorithm
the declared policy excludes or that SD-JWT never accepts (`none`,
symmetric `HS*`). Unusable declarations themselves (an empty list, dead
entries) are not errors — they simply fail closed. For key rotation,
`with_issuer_verifying_key_for_kid(kid, key)` registers additional pinned keys
selected by the token's header `kid`; an unknown or absent `kid` falls back
to the `with_issuer_verifying_key` default key when one is bound, and fails
otherwise.
The trait-level `allowed_verifying_algs` likewise stays a set so a custom
multi-key provider can accept several algorithms — each key still used with
exactly one.

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
