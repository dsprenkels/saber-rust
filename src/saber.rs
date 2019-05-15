use sha3::digest::{ExtendableOutput, Input, XofReader};

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

    fn gen_secret(seed: &[u8]) -> Vector {
        debug_assert_eq!(seed.len(), NOISE_SEEDBYTES);
        let mut hasher = sha3::Shake128::default();
        hasher.input(seed);
        let mut xof = hasher.xof_result();

        let mut secret = Vector::default();
        let mut buf = [0; 4];
        for poly in secret.polys.iter_mut() {
            for cs in poly.coeffs.chunks_exact_mut(4) {
                xof.read(&mut buf);

                let t = load_littleendian(buf);
                let mut d = 0;
                for idx in 0..4 {
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
        }
        secret
    }
}

fn load_littleendian(bytes: [u8; 4]) -> u64 {
    let mut r = 0;
    for (idx, b) in bytes.iter().enumerate() {
        r |= u64::from(*b) << (8 * idx);
    }
    r
}

#[derive(Clone)]
pub struct PublicKey {
    pk_cpa: INDCPAPublicKey,
}

impl generic::PublicKey<Saber> for PublicKey {
    fn new(pk_cpa: INDCPAPublicKey) -> PublicKey {
        PublicKey { pk_cpa }
    }

    fn pk_cpa(&self) -> &INDCPAPublicKey {
        &self.pk_cpa
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        self.pk_cpa.to_bytes().into()
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> PublicKeyBytes {
        <PublicKey as generic::PublicKey<Saber>>::to_bytes(&self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, crate::Error> {
        generic::PublicKey::from_bytes(bytes)
    }
}

impl From<&PublicKeyBytes> for PublicKey {
    fn from(newtype: &PublicKeyBytes) -> PublicKey {
        <PublicKey as generic::PublicKey<Saber>>::from_newtype(newtype)
    }
}

impl<'a> From<&'a SecretKey> for &'a PublicKey {
    fn from(sk: &SecretKey) -> &PublicKey {
        &sk.pk_cca
    }
}

__byte_array_newtype!(pub PublicKeyBytes, PUBLIC_KEY_BYTES, [u8; PUBLIC_KEY_BYTES]);

#[derive(Clone)]
pub struct SecretKey {
    z: [u8; KEYBYTES],
    hash_pk: [u8; HASHBYTES],
    pk_cca: PublicKey,
    sk_cpa: INDCPASecretKey,
}

impl generic::SecretKey<Saber> for SecretKey {
    fn new(
        z: [u8; KEYBYTES],
        hash_pk: [u8; HASHBYTES],
        pk_cca: PublicKey,
        sk_cpa: INDCPASecretKey,
    ) -> SecretKey {
        SecretKey {
            z,
            hash_pk,
            pk_cca,
            sk_cpa,
        }
    }

    fn z(&self) -> &[u8; KEYBYTES] {
        &self.z
    }
    fn hash_pk(&self) -> &[u8; HASHBYTES] {
        &self.hash_pk
    }
    fn pk_cca(&self) -> &PublicKey {
        &self.pk_cca
    }
    fn sk_cpa(&self) -> &INDCPASecretKey {
        &self.sk_cpa
    }
}

impl From<&SecretKeyBytes> for SecretKey {
    fn from(newtype: &SecretKeyBytes) -> SecretKey {
        <SecretKey as generic::SecretKey<Saber>>::from_newtype(newtype)
    }
}

impl SecretKey {
    /// Generate a saber secret key
    ///
    /// This function generates a saber secret key. It is basically an alias for
    /// [keygen](fn.keygen.html).
    ///
    /// ```
    /// let secret_key = saber::saber::SecretKey::generate();
    /// ```
    pub fn generate() -> SecretKey {
        <SecretKey as generic::SecretKey<Saber>>::generate()
    }

    pub fn to_bytes(&self) -> SecretKeyBytes {
        <SecretKey as generic::SecretKey<Saber>>::to_bytes(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, crate::Error> {
        <SecretKey as generic::SecretKey<Saber>>::from_bytes(bytes)
    }
}

__byte_array_newtype!(doc="
A secret key formatted as a byte string

This data structure is used for conversions between Saber secret keys and byte strings.
", pub SecretKeyBytes, SECRET_KEY_BYTES, [u8; SECRET_KEY_BYTES]);

#[derive(Clone)]
struct INDCPAPublicKey {
    vec: Vector,
    seed: [u8; SEEDBYTES],
}

impl generic::INDCPAPublicKey<Saber> for INDCPAPublicKey {
    fn new(vec: Vector, seed: [u8; SEEDBYTES]) -> INDCPAPublicKey {
        INDCPAPublicKey { vec, seed }
    }
    fn vec(&self) -> &Vector {
        &self.vec
    }
    fn seed(&self) -> &[u8; SEEDBYTES] {
        &self.seed
    }
}

__byte_array_newtype!(
    INDCPAPublicKeyBytes,
    INDCPA_PUBLICKEYBYTES,
    [u8; INDCPA_PUBLICKEYBYTES]
);

impl Into<PublicKeyBytes> for INDCPAPublicKeyBytes {
    fn into(self) -> PublicKeyBytes {
        PublicKeyBytes(self.0)
    }
}

#[derive(Clone)]
struct INDCPASecretKey {
    vec: Vector,
}

impl generic::INDCPASecretKey<Saber> for INDCPASecretKey {
    fn new(vec: Vector) -> INDCPASecretKey {
        INDCPASecretKey { vec }
    }

    fn vec(&self) -> Vector {
        self.vec
    }
}

__byte_array_newtype!(
    INDCPASecretKeyBytes,
    INDCPA_SECRETKEYBYTES,
    [u8; INDCPA_SECRETKEYBYTES]
);

#[derive(Clone, Copy, Debug)]
struct Matrix {
    vecs: [Vector; K],
}

impl Default for Matrix {
    #[inline]
    fn default() -> Self {
        Matrix {
            vecs: [Vector::default(); K],
        }
    }
}

impl generic::Matrix<Saber, Vector> for Matrix {
    fn vecs(&self) -> &[Vector] {
        &self.vecs
    }

    fn vecs_mut(&mut self) -> &mut [Vector] {
        &mut self.vecs[..]
    }
}

/// Vector is equivalent to the reference implementation's `polyvec` type.
#[derive(Clone, Copy, Debug, Default)]
struct Vector {
    polys: [Poly; K],
}

impl generic::Vector<Saber> for Vector {
    fn polys(&self) -> &[Poly] {
        &self.polys
    }

    fn polys_mut(&mut self) -> &mut [Poly] {
        &mut self.polys
    }
}

__byte_array_newtype!(pub Ciphertext, BYTES_CCA_DEC, [u8; BYTES_CCA_DEC]);

pub fn keygen() -> SecretKey {
    generic::keygen::<Saber>()
}

pub fn encapsulate(pk_cca: &PublicKey) -> (SharedSecret, Ciphertext) {
    generic::encapsulate::<Saber>(&pk_cca)
}

pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
    generic::decapsulate::<Saber>(ct, sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem() {
        let sk: SecretKey = keygen();
        let pk: &PublicKey = &sk.pk_cca;
        let (s1_newtype, ct): (SharedSecret, Ciphertext) = encapsulate(pk);
        let s1: [u8; KEYBYTES] = s1_newtype.into();
        let s2: [u8; KEYBYTES] = decapsulate(&ct, &sk).into();
        assert_eq!(s1, s2);
    }

    #[test]
    fn indcpa_impl() {
        let (pk, sk) = generic::indcpa_kem_keypair::<Saber>();
        for _ in 0..100 {
            let noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
            let message_received = rand::random::<[u8; 32]>();
            let ciphertext = generic::indcpa_kem_enc::<Saber>(&message_received, &noiseseed, &pk);
            let message_dec = generic::indcpa_kem_dec::<Saber>(&sk, &ciphertext);
            assert_eq!(&message_dec[..], &message_received[..]);
        }
    }

    #[test]
    fn polyveccompressedbytes_value() {
        assert_eq!(POLYVECCOMPRESSEDBYTES + SEEDBYTES, INDCPA_PUBLICKEYBYTES);
    }

    #[test]
    fn test_log_q() {
        assert_eq!(1 << (MSG2POL_CONST + 1), P);
    }
}
