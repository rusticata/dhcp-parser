# dhcp-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/dhcp-parser.svg?branch=master)](https://travis-ci.org/rusticata/dhcp-parser)

<!-- cargo-sync-readme start -->

# DHCP Parser

This crate contains a parser written in pure Rust for the DHCP protocol.

See also:
- [RFC 1541](https://tools.ietf.org/html/rfc1541): Dynamic Host Configuration Protocol
- [RFC 1533](https://tools.ietf.org/html/rfc1533): DHCP Options and BOOTP Vendor Extensions

<!-- cargo-sync-readme end -->

## Changelog

### <unreleased>

* Initial version

## Rusticata

This parser is part of the [rusticata](https://github.com/rusticata) project.
The goal of this project is to provide **safe** parsers, that can be used in other projects.

Testing of the parser is done manually, and also using unit tests and
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). Please fill a bugreport if you find any issue.

Feel free to contribute: tests, feedback, doc, suggestions (or code) of new parsers etc. are welcome.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
