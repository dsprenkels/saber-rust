use core::ops::Mul;

use crate::params::*;
use crate::poly::Poly;
use crate::SaberImplementation;

pub const RECON_SIZE: usize = 3;
pub const INDCPA_PUBKEYBYTES: usize = 992;
pub const INDCPA_SECRETKEYBYTES: usize = 1248;
pub const PUBLICKEYBYTES: usize = 992;
pub const SECRETKEYBYTES: usize = 2304;
pub const BYTES_CCA_DEC: usize = 1088;

extern "C" {
    fn indcpa_kem_keypair(pk: *mut u8, sk: *mut u8);
    fn indcpa_kem_enc(message_received: *mut u8, noiseseed: *mut u8, pk: *const u8, ciphertext: *mut u8);
    fn indcpa_kem_dec(sk: *const u8, ciphertext: *const u8, message_dec: *mut u8);
}

#[derive(Clone, Copy)]
struct Vector([Poly; RECON_SIZE]);

impl<'a> Mul<&'a Vector> for &'a Vector {
    type Output = Poly;

    /// As implemented by Algorithm 17
    fn mul(self, rhs: Self) -> Poly {
        let mut acc = Poly::new();
        for i in 0..3 {
            acc = &acc + &(&self.0[i] * &rhs.0[i]);
        }
        acc
    }
}

impl Vector {
    fn new() -> Self {
        Vector([Poly::new(); RECON_SIZE])
    }
}

#[derive(Clone, Copy)]
struct Matrix([Vector; RECON_SIZE]);

impl<'a> Mul<&'a Vector> for Matrix {
    type Output = Vector;

    /// As implemented by Algorithm 16
    fn mul(self, rhs: &'a Vector) -> Vector {
        let mut result = Vector::new();
        for i in 0..RECON_SIZE {
            result.0[i] = &self.0[i] * &rhs;
        }
        result
    }
}

pub struct Saber;

impl SaberImplementation for Saber {
    type Vector = [Poly; 3];

    // const RECON_SIZE: usize = 3;
}

#[cfg(test)]
mod tests {
    use super::*;



    /// The structs `LightSaber`, `Saber`, `FireSaber` exist to declare which
    /// set of parameters is to be used. As such, they hold no runtime data
    /// and their size in memory should be 0.
    #[test]
    fn saber_has_no_size() {
        assert_eq!(core::mem::size_of::<Saber>(), 0);
    }

    #[test]
    fn test_indcpa_keypair() {
        let mut pk = [0; PUBLICKEYBYTES];
        let mut sk = [0; SECRETKEYBYTES];
        let mut noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
        let mut message_received = [b'A'; 32];
        let mut ciphertext = [b'B'; SECRETKEYBYTES];
        let mut message_dec = [b'C'; 32];

        unsafe {
            indcpa_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
            indcpa_kem_enc(message_received.as_mut_ptr(), noiseseed.as_mut_ptr(), pk.as_ptr(), ciphertext.as_mut_ptr());
            indcpa_kem_dec(sk.as_ptr(), ciphertext.as_ptr(), message_dec.as_mut_ptr());
        }
        assert_eq!(&message_dec[..], &message_received[..]);
    }
}
