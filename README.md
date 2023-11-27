# SD-JWT Rust Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Rust.

Note: while the project is started as a reference implementation, it is intended to be evolved to a production-ready, high-performance implementations in the long-run.

## External Dependencies

Dual license (MIT/Apache 2.0) dependencies:
- [base64](https://crates.io/crates/base64)
- [log](https://crates.io/crates/log)
- [serde_json](https://crates.io/crates/serde_json)
- [sha2](https://crates.io/crates/sha2)
- [rand](https://crates.io/crates/rand)
- [hmac](https://crates.io/crates/hmac)

MIT license dependencies:
- [jsonwebtoken](https://crates.io/crates/jsonwebtoken)

Note: the list of dependencies may be changed in the future.

## Initial Maintainers

- Sergey Minaev ([Github](https://github.com/jovfer))
- DSR Corporation Decentralized Systems Team ([Github](https://github.com/orgs/DSRCorporation/teams/decentralized-systems)

## To Be Completed by Maintainers
- [ ] Create MAINTAINERS.md file using the [format documented on the TAC site](https://tac.openwallet.foundation/governance/maintainers-file-content/).
- [ ] Create a CONTRIBUTING.md file that documents steps for contributing to the project
- [ ] Create a CODEOWNERS file
- [ ] Update the README.md file as necessary