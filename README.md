# SD-JWT Rust Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification (RFC 9901)](https://www.rfc-editor.org/rfc/rfc9901.html) written in Rust.

Note: while the project is started as a reference implementation, it is intended to be evolved to a production-ready, high-performance implementations in the long-run.

## API
Note: the current version of the crate is 0.0.x, so the API should be considered as experimental.
Proposals about API improvements are highly appreciated.

```rust
fn demo() {
    let issuer_signer = Box::new(SDJWTSignerBuiltin::new(SDJWTKeyWithAlg::new(issuer_private_key, "ES256")).unwrap());
    let mut issuer = SDJWTIssuer::new(issuer_signer);
    let sd_jwt = issuer.issue_sd_jwt(claims, ClaimsForSelectiveDisclosureStrategy::AllLevels, holder_jwk, add_decoy, SDJWTSerializationFormat::Compact).unwrap();

    let holder_verifier = Box::new(SDJWTSignatureVerifierBuiltin::new(&["ES256"], None)
        .with_issuer_verifying_key(SDJWTKeyWithAlg::new(issuer_public_key.clone(), "ES256")).unwrap());
    // `None`: no Key Binding signer, as this presentation has no Key Binding JWT.
    let mut holder = SDJWTHolder::new(holder_verifier, None, sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let presentation = holder.create_presentation(claims_to_disclosure, None, None).unwrap();

    let verifier = Box::new(SDJWTSignatureVerifierBuiltin::new(&["ES256"], None)
        .with_issuer_verifying_key(SDJWTKeyWithAlg::new(issuer_public_key, "ES256")).unwrap());
    let verified_claims = SDJWTVerifier::new(verifier, presentation, None, None, SDJWTSerializationFormat::Compact).unwrap()
                            .verified_claims;
}
```

See `tests/demos.rs` for more details;

### Custom signers and signature verifiers

`SDJWTSignerBuiltin` and `SDJWTSignatureVerifierBuiltin` cover the common case
where raw key material is held in memory. To keep keys in a platform keystore,
HSM, or remote KMS — where keys are non-extractable and only the
signing/verification *operation* may cross the boundary — implement
`SDJWTSigner` and/or `SDJWTSignatureVerifier` and inject those instead:

```rust
struct KeystoreSigner { /* handle to one keystore key */ }

impl SDJWTSigner for KeystoreSigner {
    fn header(&self) -> Result<SDJWTSignerHeader> {
        // JWS `alg` of the keystore-held key and, optionally, parameters
        // identifying it: `kid`, `x5c` or `jwk`.
        Ok(SDJWTSignerHeader::new("ES256").with_kid("issuer-key-1"))
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        // Sign the raw JWS signing input with the keystore-held key.
    }
}

struct KeystoreVerifier { /* trusted keys */ }

impl SDJWTSignatureVerifier for KeystoreVerifier {
    fn allowed_algs(&self, role: SDJWTSignatureRole) -> Result<Vec<String>> {
        // Algorithm allowlist (RFC 8725 §3.1): the library rejects any JWT
        // whose header `alg` is not listed here BEFORE calling `verify`.
    }
    fn verify(&self, message: &[u8], signature: &[u8], request: &SDJWTKeyRequest) -> Result<()> {
        // Select and trust a key for the signer `request` describes.
        // `request.iss` / `kid` / `x5c` / `jwk` are UNVERIFIED input.
    }
}
```

An Issuer takes a signer; a Verifier takes a signature verifier; a Holder takes
a signature verifier for the Issuer signature and, to present with Key
Binding, a signer for the Key Binding JWT.

The library keeps ownership of all JWS encoding/decoding, header parsing
(rejecting `alg` `none` and symmetric `HS*`), `exp`/`nbf` validation, and
enforcing the verifier's algorithm allowlist; the verifier owns key
selection and trust. A signer supplies its protected header parameters:
`alg` and, to identify its key, `kid`, `x5c` or `jwk`. `typ` is set by the
library — the Issuer's (`SDJWTIssuer::with_typ`, e.g. `dc+sd-jwt`) or
`kb+jwt` for a Key Binding JWT.

The builtins bind each key to exactly one JWS algorithm (RFC 8725 §3.1) —
`SDJWTKeyWithAlg` pairs a key with its algorithm. `SDJWTSignerBuiltin::new(key)`
signs with one key; `.with_kid(kid)`, `.with_x5c(chain)` and `.with_jwk(jwk)`
write those parameters to every JWS it signs.
`SDJWTSignatureVerifierBuiltin::new(issuer_algs, holder_algs)` declares the
Issuer allowlist and, optionally, the Key Binding one (`None` when Key Binding
is not verified). For key rotation, `with_issuer_verifying_key_for_kid(kid,
key)` registers additional pinned keys selected by the token's header `kid`,
falling back to the `with_issuer_verifying_key` default key when one is
bound.

### Multiple Issuer signatures

In the General JSON Serialization (RFC 9901 §8.3) an SD-JWT can be co-signed
by several Issuers. Each signature is made like the first one — its signer's
header (`alg`, `kid`, `x5c`, `jwk`) and the Issuer's `typ` in its own
protected header. A `kid` is
optional, but the Verifier's signature verifier must tell the signers apart;
the builtin one selects keys by `kid`:

```rust
fn co_sign() {
    let sd_jwt = issuer_1.issue_sd_jwt(claims, strategy, holder_jwk, false, SDJWTSerializationFormat::GeneralJson).unwrap();
    // `issuer_2`'s signer is bound with `.with_kid("issuer-key-2")`.
    let sd_jwt = issuer_2.add_signature(&sd_jwt).unwrap();

    // A signature verifier with both keys pinned via `with_issuer_verifying_key_for_kid`.
    let verifier = SDJWTVerifier::new(signature_verifier, presentation, aud, nonce, SDJWTSerializationFormat::GeneralJson).unwrap();
}
```

`SDJWTVerifier::new` and `SDJWTHolder::new` require every signature present
to verify. `new_with_policy(.., SDJWTSignaturePolicy::Any)` accepts the
SD-JWT when at least one does, for a party that trusts only some of the
Issuers; it stops at the first signature that verifies. A signature whose
`alg` is outside the verifier's allowlist counts as a failed signature, so
`Any` skips a co-signer using an unsupported algorithm. When several
signatures fail under `Any`, their errors are combined into one
`Error::InvalidInput`.

Either way the policy covers the signatures *present*: the `signatures`
array is not integrity protected, so a co-signature can be removed or
duplicated in transit. To require specific signers, let your
`SDJWTSignatureVerifier` — the component that selects and trusts keys, by
`kid`, `x5c` or otherwise — record the keys it accepts, under
`SDJWTSignaturePolicy::All`. Malformed input — e.g. a header parameter in
both the protected and the unprotected header, `crit`, or `disclosures`
outside the first signature — is rejected under every policy.

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
