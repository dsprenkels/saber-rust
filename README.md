# Saber-rust

[![Build Status](https://travis-ci.org/dsprenkels/saber-rust.svg?branch=master)](https://travis-ci.org/dsprenkels/saber-rust)

An implementation of the Saber post-quantum key-encapsulation mechanism in Rust.

[Saber][eprint] is a post-quantum cryptographic key-encapsulation mechanism. It
has been devised by:

  - Jan-Pieter D'Anvers, KU Leuven, imec-COSIC
  - Angshuman Karmakar, KU Leuven, imec-COSIC
  - Sujoy Sinha Roy, KU Leuven, imec-COSIC
  - Frederik Vercauteren, KU Leuven, imec-COSIC

Like many others, it is one of the round-2 candidates of the [NIST Post-Quantum
Cryptography "competition"][nist].

[nist]: https://csrc.nist.gov/projects/post-quantum-cryptography/round-2-submissions
[eprint]: https://eprint.iacr.org/2018/230.pdf

## Documentation

You can find the documentation for this crate at
<https://dsprenkels.github.io/saber-rust/saber>.

## Getting started

Install this crate using Cargo by adding it to your dependencies:

```toml
[dependencies]
saber = { git = "https://github.com/dsprenkels/saber-rust" }
```

## Security and side-channel resistance

This crate contains **academic code**. That is, while I expect it to implement
the Saber scheme correctly, it has **not** ben independently audited in any way.
This is exactly the reason why this crate should not be pubished to [crates.io].

Moreover, although this crate uses the [secret-integers] crate to ensure that the implementation is constant time on the type-level, LLVM (and as such the Rust compiler) is known to introduce branches and other nasty side-channel bits.

[crates.io]: https://crates.io
[secret-integers]: https://github.com/denismerigoux/rust-secret-integers

## Questions

Feel free to send me an email on my Github associated e-mail address.
