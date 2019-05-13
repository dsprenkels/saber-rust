#![allow(clippy::suspicious_arithmetic_impl)]

extern crate rand;
extern crate sha3;

#[macro_use]
mod macros;

mod generic;
mod params;
mod poly;
pub mod saber;

#[derive(Clone, Debug)]
pub enum Error {
    BadLengthError {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
    #[doc(hidden)]
    __Nonexhaustive,
}

pub const HASHBYTES: usize = 32;
pub const KEYBYTES: usize = 32;
pub const MESSAGEBYTES: usize = 32;
pub const NOISE_SEEDBYTES: usize = 32;
pub const SEEDBYTES: usize = 32;
pub const CIPHERTEXT_BYTES: usize = 32;

