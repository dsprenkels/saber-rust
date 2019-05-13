#[allow(unused)]
use crate::generic::SaberImpl;
use crate::generic::{self, INDCPAPublicKey as INDCPAPublicKeyTrait, Vector as VectorTrait};

use crate::params::*;
use crate::poly::Poly;

use sha3::digest::{ExtendableOutput, Input, XofReader};

pub use crate::generic::SharedSecret;

struct Saber;

/// Also known as `l`
const K: usize = 3;

// KEM parameters
const PUBLIC_KEY_BYTES: usize = 992;
const SECRET_KEY_BYTES: usize = 2304;

const POLYVECCOMPRESSEDBYTES: usize = K * (N * 10) / 8;

/// Is called DELTA in the reference implemention
const RECON_SIZE: usize = 3;
const RECONBYTES_KEM: usize = (RECON_SIZE + 1) * N / 8;

const BYTES_CCA_DEC: usize = 1088;
const INDCPA_PUBLICKEYBYTES: usize = 992;
const INDCPA_SECRETKEYBYTES: usize = 1248;

impl generic::SaberImpl for Saber {
    // KEM parameters
    const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
    const SECRET_KEY_BYTES: usize = SECRET_KEY_BYTES;

    const POLYVECCOMPRESSEDBYTES: usize = POLYVECCOMPRESSEDBYTES;

    /// Is called DELTA in the reference implemention
    const RECON_SIZE: usize = RECON_SIZE;
    const RECONBYTES_KEM: usize = RECONBYTES_KEM;

    const BYTES_CCA_DEC: usize = BYTES_CCA_DEC;
    const INDCPA_PUBLICKEYBYTES: usize = INDCPA_PUBLICKEYBYTES;
    const INDCPA_SECRETKEYBYTES: usize = INDCPA_SECRETKEYBYTES;

    // Constants added in this implementation
    const MSG2POL_CONST: u8 = 9;

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
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, crate::Error> {
        generic::PublicKey::from_bytes(bytes)
    }

    pub fn to_bytes(&self) -> PublicKeyBytes {
        <PublicKey as generic::PublicKey<Saber>>::to_bytes(&self)
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
    pub fn to_bytes(&self) -> SecretKeyBytes {
        unimplemented!();
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

    fn to_bytes(&self) -> INDCPAPublicKeyBytes {
        let mut bytes = [0; INDCPA_PUBLICKEYBYTES];
        let (pk, seed) = bytes.split_at_mut(POLYVECCOMPRESSEDBYTES);
        self.vec.read_mod_p(pk);
        seed.copy_from_slice(&self.seed);
        INDCPAPublicKeyBytes(bytes)
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

    fn to_bytes(&self) -> INDCPASecretKeyBytes {
        let mut bytes = [0; INDCPA_SECRETKEYBYTES];
        self.vec.read_mod_q(&mut bytes);
        INDCPASecretKeyBytes(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != INDCPA_SECRETKEYBYTES {
            let err = crate::Error::BadLengthError {
                name: "bytes",
                actual: bytes.len(),
                expected: Saber::INDCPA_SECRETKEYBYTES,
            };
            return Err(err);
        }
        Ok(INDCPASecretKey {
            vec: Vector::from_bytes_mod_q(bytes),
        })
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

impl generic::Matrix<Vector> for Matrix {
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

impl generic::Vector for Vector {
    fn polys(&self) -> &[Poly] {
        &self.polys
    }

    fn polys_mut(&mut self) -> &mut [Poly] {
        &mut self.polys
    }

    /// This function implements BS2POLVECq, as described in Algorithm 9
    fn from_bytes_mod_q(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), K * 13 * 256 / 8);
        let mut vec = Vector::default();
        for (chunk, poly) in bytes.chunks_exact(13 * 256 / 8).zip(vec.polys.iter_mut()) {
            *poly = Poly::from_bytes_13bit(chunk);
        }
        vec
    }

    /// This function implements BS2POLVECp, as described in Algorithm 13
    fn from_bytes_mod_p(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), K * 10 * 256 / 8);
        let mut vec = Vector::default();
        for (chunk, poly) in bytes.chunks_exact(10 * 256 / 8).zip(vec.polys.iter_mut()) {
            *poly = Poly::from_bytes_10bit(chunk);
        }
        vec
    }

    /// This function implements POLVECq2BS, as described in Algorithm 10
    fn read_mod_q(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), K * 13 * 256 / 8);
        for (poly, chunk) in self.polys.iter().zip(bytes.chunks_exact_mut(13 * 256 / 8)) {
            poly.read_bytes_13bit(chunk);
        }
    }

    /// This function implements POLVECp2BS, as described in Algorithm 14
    fn read_mod_p(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), K * 10 * 256 / 8);
        for (poly, chunk) in self.polys.iter().zip(bytes.chunks_exact_mut(10 * 256 / 8)) {
            poly.read_bytes_10bit(chunk);
        }
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
}
