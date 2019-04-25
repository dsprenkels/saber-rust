/*!
This module specifies the parameters that are used for the different Saber
variants: LightSaber, Saber, and FireSaber (in order of security parameter).

At the point of writing this code, const_generics have not yet been
implemented in the language. Therefore, we will have to reimplement all the
functions that rely on different functions multiple times.
*/

pub const N: usize = 256;
pub const Q: u16 = 8192;
pub const P: u16 = 1024;
pub const SEEDBYTES: usize = 32;
pub const KEYBYTES: usize = 32;
pub const HASHBYTES: usize = 32;
pub const NOISE_SEEDBYTES: usize = 32;
