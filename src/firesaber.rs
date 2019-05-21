//! Saber key encapsulation using paranoid parameters.
//!
//! # Example
//!
//! ```
//! use saber::firesaber::{keygen, encapsulate, decapsulate};
//!
//! // Consider a server with a key pair
//! let server_secret_key = keygen();
//! let server_public_key = server_secret_key.public_key();
//!
//! // Let a client encapsulate some shared secret for the server
//! let (client_secret, ciphertext) = encapsulate(&server_public_key);
//!
//! // Have the server decrypt the ciphertext
//! let server_secret = decapsulate(&ciphertext, &server_secret_key);
//!
//! assert_eq!(client_secret.as_slice(), server_secret.as_slice());
//! ```

use secret_integers::*;
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
            let mut d = U64::from(0);
            for idx in 0..buf.len() {
                d += (t >> idx as u32) & 0x0024_9249.into();
            }

            let mut a = [U16::from(0); 4];
            let mut b = [U16::from(0); 4];
            a[0] = U16::from(d & 0x07.into());
            b[0] = U16::from((d >> 3) & 0x07.into());
            a[1] = U16::from((d >> 6) & 0x07.into());
            b[1] = U16::from((d >> 9) & 0x07.into());
            a[2] = U16::from((d >> 12) & 0x07.into());
            b[2] = U16::from((d >> 15) & 0x07.into());
            a[3] = U16::from((d >> 18) & 0x07.into());
            b[3] = U16::from((d >> 21) & 0x07.into());

            cs[0] = a[0] - b[0];
            cs[1] = a[1] - b[1];
            cs[2] = a[2] - b[2];
            cs[3] = a[3] - b[3];
        }
        poly
    }
}

__generate_non_generic_impl!(FireSaber);
__generate_non_generic_tests!(FireSaber);
