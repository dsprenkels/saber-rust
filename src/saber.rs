use sha3::digest::XofReader;

use crate::generic::{self, INDCPAPublicKey as INDCPAPublicKeyTrait};
use crate::params::*;
use crate::poly::Poly;

pub use crate::generic::SharedSecret;

struct Saber;

__generate_params!(3, 8, 3);

impl generic::SaberImpl for Saber {
    __params_impl!();

    type Vector = Vector;
    type Matrix = Matrix;

    type PublicKey = PublicKey;
    type SecretKey = SecretKey;

    type PublicKeyBytes = PublicKeyBytes;
    type SecretKeyBytes = SecretKeyBytes;

    type INDCPAPublicKey = INDCPAPublicKey;
    type INDCPASecretKey = INDCPASecretKey;

    type INDCPAPublicKeyBytes = INDCPAPublicKeyBytes;
    type INDCPASecretKeyBytes = INDCPASecretKeyBytes;

    type Ciphertext = Ciphertext;

    fn recon_poly_read_bytes_xbit(poly: Poly, buf: &mut [u8]) {
        poly.read_bytes_4bit(buf)
    }

    fn recon_poly_from_bytes_xbit(buf: &[u8]) -> Poly {
        Poly::from_bytes_4bit(buf)
    }

    fn cbd<T: XofReader>(xof: &mut T) -> Poly {
        let mut poly = Poly::default();
        for cs in poly.coeffs.chunks_exact_mut(4) {
            let mut buf = [0; 4];
            xof.read(&mut buf);

            let t = generic::load_littleendian(&buf);
            let mut d = 0;
            for idx in 0..buf.len() {
                d += (t >> idx) & 0x1111_1111;
            }

            let mut a = [0; 4];
            let mut b = [0; 4];
            a[0] = (d & 0xF) as u16;
            b[0] = ((d >> 4) & 0xF) as u16;
            a[1] = ((d >> 8) & 0xF) as u16;
            b[1] = ((d >> 12) & 0xF) as u16;
            a[2] = ((d >> 16) & 0xF) as u16;
            b[2] = ((d >> 20) & 0xF) as u16;
            a[3] = ((d >> 24) & 0xF) as u16;
            b[3] = (d >> 28) as u16;

            cs[0] = (a[0]).wrapping_sub(b[0]);
            cs[1] = (a[1]).wrapping_sub(b[1]);
            cs[2] = (a[2]).wrapping_sub(b[2]);
            cs[3] = (a[3]).wrapping_sub(b[3]);
        }
        poly
    }
}

__generate_non_generic_impl!(Saber);
__generate_non_generic_tests!(Saber);

#[cfg(test)]
#[cfg(feature = "reftest")]
mod tests {
    use rand_os::rand_core::RngCore;
    use super::*;

    mod ffi {
        #![allow(dead_code)]

        use super::*;

        extern "C" {
            pub(super) fn indcpa_kem_keypair(
                pk: *mut INDCPAPublicKeyBytes,
                sk: *mut INDCPASecretKeyBytes,
            );
            pub(super) fn indcpa_kem_enc(
                message_received: *mut u8,
                noiseseed: *mut u8,
                pk: *const INDCPAPublicKeyBytes,
                ciphertext: *mut u8,
            );
            pub(super) fn indcpa_kem_dec(
                sk: *const INDCPASecretKeyBytes,
                ciphertext: *const u8,
                message_dec: *mut u8,
            );
        }
    }

    #[test]
    fn test_indcpa_kem_enc() {
        use crate::generic::indcpa_kem_enc;

        for _ in 0..100 {
            let sk = keygen();
            let pk = sk.public_key();
            let indcpa_pk = &pk.pk_cpa;
            let indcpa_pk_bytes = indcpa_pk.to_bytes();

            let mut rng = rand_os::OsRng::new().unwrap();
            let mut message_received = [0; KEYBYTES];
            rng.fill_bytes(&mut message_received);
            let mut noiseseed = [0; NOISE_SEEDBYTES];
            rng.fill_bytes(&mut noiseseed);

            let ciphertext = indcpa_kem_enc::<Saber>(&message_received, &noiseseed, indcpa_pk);
            let mut ciphertext2 = [0; BYTES_CCA_DEC];

            unsafe {
                ffi::indcpa_kem_enc(
                    message_received.as_mut_ptr(),
                    noiseseed.as_mut_ptr(),
                    &indcpa_pk_bytes as *const INDCPAPublicKeyBytes,
                    ciphertext2.as_mut_ptr(),
                );
            }
            assert_eq!(ciphertext.as_slice(), &ciphertext2[..]);
        }
    }

    #[test]
    fn test_indcpa_kem_dec() {
        use crate::generic::{indcpa_kem_dec, indcpa_kem_enc, INDCPASecretKey};

        for _ in 0..100 {
            let sk = keygen();
            let indcpa_sk = &sk.sk_cpa;
            let indcpa_sk_bytes = indcpa_sk.to_bytes();
            let pk = sk.public_key();
            let indcpa_pk = &pk.pk_cpa;

            let mut rng = rand_os::OsRng::new().unwrap();
            let mut message_received = [0; KEYBYTES];
            rng.fill_bytes(&mut message_received);
            let mut noiseseed = [0; NOISE_SEEDBYTES];
            rng.fill_bytes(&mut noiseseed);

            let ciphertext = indcpa_kem_enc::<Saber>(&message_received, &noiseseed, indcpa_pk);
            let mut message_dec2: [u8; KEYBYTES] = [0; KEYBYTES];
            let message_dec = indcpa_kem_dec::<Saber>(indcpa_sk, &ciphertext);

            unsafe {
                ffi::indcpa_kem_dec(
                    &indcpa_sk_bytes as *const INDCPASecretKeyBytes,
                    ciphertext.0.as_ptr(),
                    message_dec2.as_mut_ptr(),
                );
            }
            assert_eq!(&message_dec[..], &message_dec2[..]);
        }
    }

}
