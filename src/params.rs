/*!
This module specifies the parameters that are used for the different Saber
variants: LightSaber, Saber, and FireSaber (in order of security parameter).

At the point of writing this code, const_generics have not yet been
implemented in the language. Therefore, we will have to reimplement all the
functions that rely on different functions multiple times.
*/

// Universal constants
pub const N: usize = 256;
pub const Q: u16 = 8192;
pub const P: u16 = 1024;

pub const EPS_Q: u8 = 13;
pub const EPS_P: u8 = 10;

// Buffer lengths
pub const COINBYTES: usize = 32;
pub const HASHBYTES: usize = 32;
pub const KEYBYTES: usize = 32;
pub const MESSAGEBYTES: usize = 32;
pub const NOISE_SEEDBYTES: usize = 32;
pub const SEEDBYTES: usize = 32;

// Constants added in this implementation
pub const MSG2POL_CONST: u8 = 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_q() {
        assert_eq!(1 << (MSG2POL_CONST + 1), P);
    }
}
