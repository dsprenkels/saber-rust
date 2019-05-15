#![allow(clippy::suspicious_arithmetic_impl)]

extern crate rand;
extern crate sha3;

#[macro_use]
mod newtype;

#[macro_use]
mod params;

mod generic;
// pub mod lightsaber;
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
