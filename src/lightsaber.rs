//! Saber key encapsulation using lightweight parameters.
//!
//! # Example
//!
//! ```
//! use saber::lightsaber::{keygen, encapsulate, decapsulate};
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

struct LightSaber;

__generate_params!(2, 10, 2);

impl generic::SaberImpl for LightSaber {
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
        poly.read_bytes_3bit(buf)
    }

    fn recon_poly_from_bytes_xbit(buf: &[u8]) -> Poly {
        Poly::from_bytes_3bit(buf)
    }

    fn cbd<T: XofReader>(xof: &mut T) -> Poly {
        let mut poly = Poly::default();
        for cs in poly.coeffs.chunks_exact_mut(4) {
            let mut buf = [0; 5];
            xof.read(&mut buf);

            let t = generic::load_littleendian(&buf);
            let mut d = U64::from(0);
            for idx in 0..buf.len() {
                d += (t >> idx as u32) & 0x0008_4210_8421.into();
            }

            let mut a = [U16::from(0); 4];
            let mut b = [U16::from(0); 4];
            a[0] = U16::from(d & 0x1F.into());
            b[0] = U16::from((d >> 5) & 0x1F.into());
            a[1] = U16::from((d >> 10) & 0x1F.into());
            b[1] = U16::from((d >> 15) & 0x1F.into());
            a[2] = U16::from((d >> 20) & 0x1F.into());
            b[2] = U16::from((d >> 25) & 0x1F.into());
            a[3] = U16::from((d >> 30) & 0x1F.into());
            b[3] = U16::from(d >> 35);

            cs[0] = a[0] - b[0];
            cs[1] = a[1] - b[1];
            cs[2] = a[2] - b[2];
            cs[3] = a[3] - b[3];
        }
        poly
    }
}

__generate_non_generic_impl!(LightSaber);
__generate_non_generic_tests!(LightSaber);
