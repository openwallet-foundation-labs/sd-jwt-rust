# SD-JWT Rust Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Rust.
Supported version: 7.

Note: while the project is started as a reference implementation, it is intended to be evolved to a production-ready, high-performance implementations in the long-run.

## API
Note: the current version of the crate is 0.0.x, so the API should be considered as experimental.
Proposals about API improvements are highly appreciated.

```rust
fn demo() {
    let mut issuer = SDJWTIssuer::new(issuer_key, None);
    let sd_jwt = issuer.issue_sd_jwt(claims, ClaimsForSelectiveDisclosureStrategy::AllLevels, holder_key, add_decoy, SDJWTSerializationFormat::Compact).unwrap();

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact).unwrap();
    let presentation = holder.create_presentation(claims_to_disclosure, None, None, None, None).unwrap();

    let verified_claims = SDJWTVerifier::new(presentation, cb_to_resolve_issuer_key, None, None, SDJWTSerializationFormat::Compact).unwrap()
                            .verified_claims;
}
```

See `tests/demos.rs` for more details;

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
