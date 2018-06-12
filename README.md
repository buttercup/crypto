# Buttercup Crypto [![Crates.io version][crates-image]][crates-url] [![Build Status][travis-image]][travis-url]

This library contains encryption tools to be used in Buttercup products and services. These tools are written and maintained in Rust to ensure consistency and performance across all of the products.

We use a [modified version](https://github.com/buttercup/rust-crypto-wasm) of the `rust-crypto` library to make compiling to WASM targets possible. This dependency will be changed/removed once it's possible to use more mature encryption libraries (like `ring`) in WebAssembly. But the interfaces won't change.

## Current Features

- Key Derivation (pbkdf2)
- CBC Encryption/Decryption
- GCM Encryption/Decryption
- Hmac

## License

This software is released under the [MIT License](LICENSE).

[crates-image]: https://img.shields.io/crates/v/buttercup-crypto.svg
[crates-url]: https://crates.io/crates/buttercup-crypto
[travis-image]: https://travis-ci.org/buttercup/crypto.svg?branch=master
[travis-url]: https://travis-ci.org/buttercup/crypto
