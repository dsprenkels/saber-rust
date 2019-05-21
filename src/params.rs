/*!
This module specifies the parameters that are used for the different Saber
variants: LightSaber, Saber, and FireSaber (in order of security parameter).

At the point of writing this code, const_generics have not yet been
implemented in the language. Therefore, we will have to reimplement all the
functions that rely on different functions multiple times.
*/

// Universal constants
pub(crate) const N: usize = 256;
pub(crate) const P: u16 = 1024;

pub(crate) const EPS_P: u8 = 10;
pub(crate) const EPS_Q: u8 = 13;

// Buffer lengths
pub(crate) const COINBYTES: usize = 32;
pub(crate) const HASHBYTES: usize = 32;
pub(crate) const KEYBYTES: usize = 32;
pub(crate) const MESSAGEBYTES: usize = 32;
pub(crate) const NOISE_SEEDBYTES: usize = 32;
pub(crate) const SEEDBYTES: usize = 32;

// Constants added in this implementation
pub(crate) const MSG2POL_CONST: u8 = 9;

macro_rules! __generate_params {
    ($k:expr, $mu:expr, $delta:expr) => {
        const K: usize = $k;
        const MU: usize = $mu;
        const RECON_SIZE: usize = $delta;

        const POLYVECCOMPRESSEDBYTES: usize =
            K * (crate::params::N * crate::params::EPS_P as usize) / 8;
        const INDCPA_PUBLICKEYBYTES: usize = POLYVECCOMPRESSEDBYTES + crate::params::SEEDBYTES;
        const INDCPA_SECRETKEYBYTES: usize =
            K * crate::params::EPS_Q as usize * crate::params::N / 8;

        // KEM parameters
        const PUBLIC_KEY_BYTES: usize = INDCPA_PUBLICKEYBYTES;
        const SECRET_KEY_BYTES: usize = INDCPA_SECRETKEYBYTES
            + INDCPA_PUBLICKEYBYTES
            + crate::params::HASHBYTES
            + crate::params::KEYBYTES;
        const BYTES_CCA_DEC: usize = POLYVECCOMPRESSEDBYTES + RECONBYTES_KEM;

        /// Is called DELTA in the reference implemention
        const RECONBYTES_KEM: usize = (RECON_SIZE + 1) * crate::params::N / 8;
    };
}

macro_rules! __params_impl {
    () => {
        const K: usize = K;
        const MU: usize = MU;
        const RECON_SIZE: usize = RECON_SIZE;
        const POLYVECCOMPRESSEDBYTES: usize = POLYVECCOMPRESSEDBYTES;
        const INDCPA_PUBLICKEYBYTES: usize = INDCPA_PUBLICKEYBYTES;
        const INDCPA_SECRETKEYBYTES: usize = INDCPA_SECRETKEYBYTES;
        const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
        const SECRET_KEY_BYTES: usize = SECRET_KEY_BYTES;
        const BYTES_CCA_DEC: usize = BYTES_CCA_DEC;
        const RECONBYTES_KEM: usize = RECONBYTES_KEM;
    };
}
