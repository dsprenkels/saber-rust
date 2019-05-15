#![allow(clippy::suspicious_arithmetic_impl)]

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

pub mod firesaber;
pub mod lightsaber;
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
