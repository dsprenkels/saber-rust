/*!
This crate implements the Saber post-quantum key-encapsulation mechanism.

[Saber][eprint] is a post-quantum cryptographic key-encapsulation mechanism. It has been devised
by:
  - Jan-Pieter D'Anvers, KU Leuven, imec-COSIC
  - Angshuman Karmakar, KU Leuven, imec-COSIC
  - Sujoy Sinha Roy, KU Leuven, imec-COSIC
  - Frederik Vercauteren, KU Leuven, imec-COSIC

Like many others, it is one of the round-2 candidates of the [NIST Post-Quantum Cryptography
"competition"][nist].

# Getting started

Install this crate using Cargo by adding it to your dependencies:

```toml
[dependencies]
saber = { git = "https://github.com/dsprenkels/saber-rust" }
```

Then, choose one of the parameter sets by importing them into your code:

```rust
extern crate saber;

use saber::saber::{keygen, encapsulate, decapsulate};
```

Now you can use the functions [`keygen`], [`encapsulate`] and [`decapsulate`] to agree on a shared
secret key between two endpoints.

```rust
# extern crate saber;
# use ::saber::saber::{keygen, encapsulate, decapsulate};

// Consider a server with a key pair
let server_secret_key = keygen();
let server_public_key = server_secret_key.public_key();

// Let a client encapsulate some shared secret for the server
let (client_secret, ciphertext) = encapsulate(&server_public_key);

// Have the server decrypt the ciphertext
let server_secret = decapsulate(&ciphertext, &server_secret_key);

assert_eq!(client_secret.as_slice(), server_secret.as_slice());
```

# (De)serializing keys

Both [`PublicKey`] and [`SecretKey`] can be stored into arrays using [`PublicKey::to_bytes`] and
[`SecretKey::to_bytes`] respectively. To load a key back from a `&[u8]` buffer, use
[`PublicKey::from_bytes`] and [`SecretKey::from_bytes`]. For example:

```rust
# let secret_key = ::saber::saber::keygen();
let public_key = secret_key.public_key();

use saber::saber::{PublicKey, encapsulate};

// Store the public key
let public_key_bytes = public_key.to_bytes().into_bytes();
println!("Saber public key: {:02x?}", &public_key_bytes[..]);

// Lose the original public-key struct
drop(public_key);

// Reload the public key
let public_key = match PublicKey::from_bytes(&public_key_bytes) {
    Ok(pk) => pk,
    Err(err) => panic!("Error decoding public key: {}", err),
};

// Now you can use the key again for key encapsulation
let (client_secret, ciphertext) = encapsulate(&public_key);
```

[nist]: https://csrc.nist.gov/projects/post-quantum-cryptography/round-2-submissions
[eprint]: https://eprint.iacr.org/2018/230.pdf
[`keygen`]: saber/fn.keygen.html
[`encapsulate`]: saber/fn.encapsulate.html
[`decapsulate`]: saber/fn.decapsulate.html
[`PublicKey`]: saber/struct.PublicKey.html
[`SecretKey`]: saber/struct.SecretKey.html
[`PublicKey::to_bytes`]: saber/struct.PublicKey.html#method.to_bytes
[`SecretKey::to_bytes`]: saber/struct.SecretKey.html#method.to_bytes
[`PublicKey::from_bytes`]: saber/saber/struct.PublicKey.html#method.from_bytes
[`SecretKey::from_bytes`]: saber/saber/struct.SecretKey.html#method.from_bytes
*/

#![allow(clippy::suspicious_arithmetic_impl)]

use core::fmt::Formatter;

extern crate rand_os;
extern crate secret_integers;
extern crate sha3;

#[macro_use]
mod newtype;

#[macro_use]
mod params;

#[macro_use]
mod non_generic;

mod generic;
mod poly;

pub mod saber;
pub mod lightsaber;
pub mod firesaber;

/// Error type for the [saber crate].
///
/// [saber crate]: index.html
#[derive(Clone, Debug)]
pub enum Error {
    /// This error indicates that the length of a slice that was provided to some function was
    /// incorrect.
    ///
    /// For convenience, `BadLength` will be filled with some useful values. `name` contains
    /// the name of the slice that had an invalid length. It was expected to be `expected` items
    /// long, but the actual size was `actual`.
    BadLength {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
    #[doc(hidden)]
    __Nonexhaustive,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Error::BadLength {
                name,
                actual,
                expected,
            } => write!(
                f,
                "error: {} should be {} element long, not {}",
                name, expected, actual
            ),
            Error::__Nonexhaustive => {
                unreachable!("Error::__Nonexhaustive should never have been constructed")
            }
        }
    }
}

impl std::error::Error for Error {}
