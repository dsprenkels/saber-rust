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
        unimplemented!()
    }

    fn recon_poly_from_bytes_xbit(buf: &[u8]) -> Poly {
        unimplemented!()
    }

    fn cbd<T: XofReader>(xof: &mut T) -> Poly {
        unimplemented!()
    }
}

__generate_non_generic_impl!(FireSaber);
__generate_non_generic_tests!(FireSaber);