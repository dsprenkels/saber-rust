use sha3::digest::XofReader;

use crate::generic::{self, INDCPAPublicKey as INDCPAPublicKeyTrait};
use crate::params::*;
use crate::poly::Poly;

pub use crate::generic::SharedSecret;

struct FireSaber;

__generate_params!(4, 6, 5);

impl generic::SaberImpl for FireSaber {
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
        poly.read_bytes_6bit(buf)
    }

    fn recon_poly_from_bytes_xbit(buf: &[u8]) -> Poly {
        Poly::from_bytes_6bit(buf)
    }

    fn cbd<T: XofReader>(xof: &mut T) -> Poly {
        let mut poly = Poly::default();
        for cs in poly.coeffs.chunks_exact_mut(4) {
            let mut buf = [0; 3];
            xof.read(&mut buf);

            let t = generic::load_littleendian(&buf);
            let mut d = 0;
            for idx in 0..buf.len() {
                d += (t >> idx) & 0x249249;
            }

            let mut a = [0; 4];
            let mut b = [0; 4];
            a[0] = (d & 0x07) as u16;
            b[0] = ((d >> 3) & 0x07) as u16;
            a[1] = ((d >> 6) & 0x07) as u16;
            b[1] = ((d >> 9) & 0x07) as u16;
            a[2] = ((d >> 12) & 0x07) as u16;
            b[2] = ((d >> 15) & 0x07) as u16;
            a[3] = ((d >> 18) & 0x07) as u16;
            b[3] = ((d >> 21) & 0x07) as u16;

            cs[0] = (a[0]).wrapping_sub(b[0]);
            cs[1] = (a[1]).wrapping_sub(b[1]);
            cs[2] = (a[2]).wrapping_sub(b[2]);
            cs[3] = (a[3]).wrapping_sub(b[3]);
        }
        poly
    }
}

__generate_non_generic_impl!(FireSaber);
__generate_non_generic_tests!(FireSaber);
