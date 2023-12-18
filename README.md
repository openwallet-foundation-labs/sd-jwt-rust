# SD-JWT Rust Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Rust.

Note: while the project is started as a reference implementation, it is intended to be evolved to a production-ready, high-performance implementations in the long-run.

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
TBD

## API
Note: the current version of the crate is 0.0.x, so the API should be considered as experimental.
Proposals about API improvements are highly appreciated.

TBD

## Functionality

Please refer to the list, unchecked items are in progress and will be supported soon
- [x] Issuance of SD-JWT
- [x] Presentation of SD-JWT with custom schema
- [x] Verification of SD-JWT
- [x] CI pipelines for Ubuntu
- [ ] Support of multiple hash / sign algorithms
- [ ] JWT Key Binding support
- [x] Selective disclosure of arrays elements
- [ ] Extended error handling
- [ ] Extended CI/CD

## External Dependencies

Dual license (MIT/Apache 2.0)
dependencies: [base64](https://crates.io/crates/base64), [lazy_static](https://crates.io/crates/lazy_static) [log](https://crates.io/crates/log), [serde_json](https://crates.io/crates/serde_json), [sha2](https://crates.io/crates/sha2), [rand](https://crates.io/crates/rand), [hmac](https://crates.io/crates/hmac), [thiserror](https://crates.io/crates/thiserror).
MIT license dependencies: [jsonwebtoken](https://crates.io/crates/jsonwebtoken), [strum](https://crates.io/crates/strum)

Note: the list of dependencies may be changed in the future.

## Initial Maintainers

- Sergey Minaev ([Github](https://github.com/jovfer))
- DSR Corporation Decentralized Systems Team ([Github](https://github.com/orgs/DSRCorporation/teams/decentralized-systems))

## To Be Completed by Maintainers
- [x] Create MAINTAINERS.md file using the [format documented on the TAC site](https://tac.openwallet.foundation/governance/maintainers-file-content/).
- [ ] Create a CONTRIBUTING.md file that documents steps for contributing to the project
- [X] Create a CODEOWNERS file
- [X] Update the README.md file as necessary