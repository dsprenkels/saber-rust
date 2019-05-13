use crate::params::*;
use crate::poly::Poly;
use crate::traits::{self, INDCPAPublicKey as INDCPAPublicKeyTrait, Vector as VectorTrait, SaberImpl};

use core::ops::{Add, Mul, Shr};
use sha3::digest::{ExtendableOutput, Input, XofReader};

struct Saber;

/// Also known as `l`
const K: usize = 3;

const MU: usize = 8;
/// Is called DELTA in the reference implemention
const RECON_SIZE: usize = 3;
const POLYVECCOMPRESSEDBYTES: usize = K * (N * 10) / 8;
const CIPHERTEXTBYTES: usize = POLYVECCOMPRESSEDBYTES;
const RECONBYTES: usize = RECON_SIZE * N / 8;
const RECONBYTES_KEM: usize = (RECON_SIZE + 1) * N / 8;
const BYTES_CCA_DEC: usize = 1088;
const INDCPA_PUBLICKEYBYTES: usize = 992;
const INDCPA_SECRETKEYBYTES: usize = 1248;

impl traits::SaberImpl for Saber {
    // KEM parameters
    // const PUBLIC_KEY_BYTES: usize = 992;
    // const SECRET_KEY_BYTES: usize = 2304;

    const POLYVECCOMPRESSEDBYTES: usize = POLYVECCOMPRESSEDBYTES;
    const PUBLIC_KEY_BYTES: usize = PUBLIC_KEY_BYTES;
    const SECRET_KEY_BYTES: usize = SECRET_KEY_BYTES;
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

    /// Returns a tuple (public_key, secret_key), of PublicKey, SecretKey objects
    // C type in reference: void indcpa_kem_keypair(unsigned char *pk, unsigned char *sk);
    fn indcpa_kem_keypair() -> (INDCPAPublicKey, INDCPASecretKey) {
        let seed: [u8; SEEDBYTES] = rand::random();
        let noiseseed: [u8; COINBYTES] = rand::random();

        let a = gen_matrix(&seed);
        let sk_vec = gen_secret(&noiseseed);

        // Compute b (called `res` in reference implementation)
        let pk_vec = a.mul(sk_vec);

        // Rounding of b
        let pk_vec = (pk_vec + 4) >> 3;

        (
            INDCPAPublicKey { vec: pk_vec, seed },
            INDCPASecretKey { vec: sk_vec },
        )
    }

    // C type in reference: void indcpa_kem_enc(unsigned char *message_received, unsigned char *noiseseed, const unsigned char *pk, unsigned char *ciphertext)
    fn indcpa_kem_enc(
        message_received: &[u8],
        noiseseed: &[u8],
        pk: &INDCPAPublicKey,
    ) -> Ciphertext {
        debug_assert_eq!(message_received.len(), KEYBYTES);
        debug_assert_eq!(noiseseed.len(), NOISE_SEEDBYTES);

        let mut ciphertext = [0; BYTES_CCA_DEC];

        // CipherText_cpa = (rec || ct)
        let (ct, rec) = ciphertext.split_at_mut(POLYVECCOMPRESSEDBYTES);

        // A = GenMatrix(seed_A)
        let a = gen_matrix(&pk.seed);

        // s' = GenSecret(seed_s')
        let sk_vec = gen_secret(&noiseseed);

        // Compute b' (called `res` in reference implementation)
        let mut pk_vec = a.mul_transpose(sk_vec);

        // Rounding of b' into v_p
        pk_vec = (pk_vec + 4) >> 3;

        // ct = POLVECp2BS(v_p)
        pk_vec.read_mod_p(ct);

        // v' = BS2POLVECp(pk)
        let v1_vec = pk.vec;

        // pol_p = VectorMul(v', s', p)
        let pol_p = v1_vec * sk_vec;

        // m_p = MSG2POL(m)
        let mut m_p = Poly::from_msg(message_received);

        // m_p = m_p + pol_p mod p
        m_p = m_p + pol_p;

        // rec = ReconDataGen(m_p)
        recon_data_gen(rec, &m_p);

        Ciphertext(ciphertext)
    }

    // C type in reference: void indcpa_kem_dec(const unsigned char *sk, const unsigned char *ciphertext, unsigned char message_dec[])
    fn indcpa_kem_dec(sk: &INDCPASecretKey, ciphertext: &Ciphertext) -> [u8; MESSAGEBYTES] {
        // Extract (rec || ct) = CipherText
        let (ct, _) = ciphertext.as_slice().split_at(POLYVECCOMPRESSEDBYTES);
        let mut rec = [0; RECONBYTES_KEM];
        rec.copy_from_slice(&ciphertext.as_slice()[POLYVECCOMPRESSEDBYTES..]);

        // Unpack the secret key from the full SecretKey buffer
        let sk_vec = sk.vec;

        // b = BS2BOLVECp(ct)
        let b_vec = Vector::from_bytes_mod_p(ct);

        // v' = VectorMul(b, s, p)
        let v1 = b_vec * sk_vec;

        // m' = Recon(rec, v')
        let message_dec_unpacked = recon(&rec, &v1);

        // m = POL2MSG(m')
        let mut message_dec = [0; MESSAGEBYTES];
        message_dec_unpacked.read_bytes_msg(&mut message_dec);
        message_dec
    }
}

#[derive(Clone)]
pub struct PublicKey {
    pk_cpa: INDCPAPublicKey,
}

impl traits::PublicKey<Saber> for PublicKey {
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

impl<'a> From<&'a SecretKey> for &'a PublicKey where {
    fn from(sk: &SecretKey) -> &PublicKey {
        &sk.pk_cca
    }
}

byte_array_newtype!(PublicKeyBytes, PUBLIC_KEY_BYTES, [u8; PUBLIC_KEY_BYTES]);

#[derive(Clone)]
pub struct SecretKey {
    z: [u8; KEYBYTES],
    hash_pk: [u8; HASHBYTES],
    pk_cca: PublicKey,
    sk_cpa: INDCPASecretKey,
}

impl traits::SecretKey<Saber> for SecretKey {
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

    fn to_bytes(&self) -> SecretKeyBytes {
        unimplemented!()
    }
}

byte_array_newtype!(SecretKeyBytes, SECRET_KEY_BYTES, [u8; SECRET_KEY_BYTES]);

#[derive(Clone)]
struct INDCPAPublicKey {
    vec: Vector,
    seed: [u8; SEEDBYTES],
}

impl traits::INDCPAPublicKey<Saber> for INDCPAPublicKey {
    fn new(vec: Vector, seed: [u8; SEEDBYTES]) -> INDCPAPublicKey {
        INDCPAPublicKey { vec, seed }
    }

    fn to_bytes(&self) -> INDCPAPublicKeyBytes {
        let mut bytes = [0; INDCPA_PUBLICKEYBYTES];
        let (pk, seed) = bytes.split_at_mut(POLYVECCOMPRESSEDBYTES);
        self.vec.read_mod_p(pk);
        seed.copy_from_slice(&self.seed);
        INDCPAPublicKeyBytes(bytes)
    }
}

byte_array_newtype!(
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

impl traits::INDCPASecretKey<Saber> for INDCPASecretKey {}

impl INDCPASecretKey {
    pub fn to_bytes(&self) -> INDCPASecretKeyBytes {
        let mut bytes = [0; INDCPA_SECRETKEYBYTES];
        self.vec.read_mod_q(&mut bytes);
        INDCPASecretKeyBytes(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), INDCPA_SECRETKEYBYTES);
        INDCPASecretKey {
            vec: Vector::from_bytes_mod_q(bytes),
        }
    }
}

byte_array_newtype!(
    INDCPASecretKeyBytes,
    INDCPA_SECRETKEYBYTES,
    [u8; INDCPA_SECRETKEYBYTES]
);

#[derive(Clone, Copy, Debug)]
struct Matrix {
    vecs: [Vector; K],
}

impl Add<u16> for Matrix {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: u16) -> Matrix {
        for vec in self.vecs.iter_mut() {
            *vec = *vec + rhs;
        }
        self
    }
}

impl Default for Matrix {
    #[inline]
    fn default() -> Self {
        Matrix {
            vecs: [Vector::default(); K],
        }
    }
}

impl traits::Matrix<Saber> for Matrix {}

impl Matrix {
    /// As implemented by Algorithm 16
    #[inline]
    fn mul(mut self, rhs: Vector) -> Vector {
        let mut result = Vector::default();
        for (vec, result_vec) in self.vecs.iter_mut().zip(result.polys.iter_mut()) {
            *result_vec = *vec * rhs;
        }
        result
    }

    /// As implemented by Algorithm 16
    #[inline]
    fn mul_transpose(self, rhs: Vector) -> Vector {
        let mut result = Vector::default();
        for i in 0..K {
            for j in 0..K {
                result.polys[i] = result.polys[i] + self.vecs[j].polys[i] * rhs.polys[j];
            }
        }
        result
    }
}

impl Shr<u8> for Matrix {
    type Output = Self;

    #[inline]
    fn shr(self, rhs: u8) -> Self {
        let Matrix { mut vecs } = self;
        for vec in vecs.iter_mut() {
            *vec = *vec >> rhs;
        }
        Matrix { vecs }
    }
}

/// Vector is equivalent to the reference implementation's `polyvec` type.
#[derive(Clone, Copy, Debug)]
struct Vector {
    polys: [Poly; K],
}

impl Add<Vector> for Vector {
    type Output = Vector;

    fn add(self, rhs: Self) -> Vector {
        let Vector { mut polys } = self;
        for (coeff, other) in polys.iter_mut().zip(rhs.polys.iter()) {
            *coeff = *coeff + *other;
        }
        Vector { polys }
    }
}

impl Add<u16> for Vector {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u16) -> Vector {
        let Vector { mut polys } = self;
        for poly in polys.iter_mut() {
            *poly = *poly + rhs;
        }
        Vector { polys }
    }
}

impl Mul<Vector> for Vector {
    type Output = Poly;

    /// As implemented by Algorithm 17
    #[inline]
    fn mul(self, rhs: Self) -> Poly {
        let Vector { mut polys } = self;
        let mut acc = Poly::default();
        for (poly, other) in polys.iter_mut().zip(rhs.polys.iter()) {
            acc = acc + (*poly * *other);
        }
        acc
    }
}

impl Shr<u8> for Vector {
    type Output = Self;

    #[inline]
    fn shr(mut self, rhs: u8) -> Self {
        for poly in self.polys.iter_mut() {
            *poly = *poly >> rhs;
        }
        self
    }
}

impl Default for Vector {
    fn default() -> Self {
        Vector {
            polys: [Poly::default(); K],
        }
    }
}

impl traits::Vector<Saber> for Vector {
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

byte_array_newtype!(Ciphertext, BYTES_CCA_DEC, [u8; BYTES_CCA_DEC]);

// IMPLEMENTATION

fn gen_matrix(seed: &[u8]) -> Matrix {
    debug_assert_eq!(seed.len(), SEEDBYTES);

    let mut hasher = sha3::Shake128::default();
    hasher.input(seed);
    let mut xof = hasher.xof_result();

    let mut matrix = Matrix::default();
    for vec in matrix.vecs.iter_mut() {
        for poly in vec.polys.iter_mut() {
            let mut buf = [0; 13 * N / 8];
            xof.read(&mut buf);
            *poly = Poly::from_bytes_13bit(&buf);
        }
    }
    matrix
}

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

fn load_littleendian(bytes: [u8; 4]) -> u64 {
    let mut r = 0;
    for (idx, b) in bytes.iter().enumerate() {
        r |= u64::from(*b) << (8 * idx);
    }
    r
}

/// This function implements ReconDataGen, as described in Algorithm 19
fn recon_data_gen(dest: &mut [u8], poly: &Poly) {
    debug_assert_eq!(dest.len(), RECONBYTES_KEM);
    const C: u8 = EPS_P - RECON_SIZE as u8 - 1;
    (poly.reduce(P) >> C).read_bytes_4bit(dest);
}

/// This function implement Recon, as described in Algorithm 20
fn recon(rec: &[u8], poly: &Poly) -> Poly {
    debug_assert_eq!(rec.len(), RECONBYTES_KEM);
    const C0: u8 = EPS_P - RECON_SIZE as u8 - 1;
    const C1: u16 = (1 << (EPS_P - 2)) - (1 << (EPS_P - 2 - RECON_SIZE as u8));

    let rec_poly = Poly::from_bytes_4bit(rec);
    let mut k_poly = Poly::default();
    let input_iter = rec_poly.coeffs.iter().zip(poly.coeffs.iter());
    for ((recbit, coeff), k) in input_iter.zip(k_poly.coeffs.iter_mut()) {
        let temp = recbit << C0;
        let temp = coeff.wrapping_sub(temp).wrapping_add(C1);
        //                   temp
        // K_i = floor( --------------- )
        //              2^[log2(p) - 1]
        //
        // Observe that 2^[log2(p) - 1] is just (P/2), so K_i = 2*temp/P.
        // I.e. we calculate that by computing K_i ← temp >> (𝜖_p - 1).
        // *k |= (((temp >> (EPS_P - 1)) & 0x1) as u8) << idx;
        *k |= (temp >> (EPS_P - 1)) & 0x1;
    }
    k_poly
}

#[cfg(test)]
mod tests {
    use super::*;
    use traits::{decapsulate, encapsulate, keygen};

    use crate::common::SharedSecret;

    #[test]
    fn test_kem() {
        let sk: SecretKey = keygen::<Saber>();
        let pk: &PublicKey = &sk.pk_cca;
        let (s1, ct): (SharedSecret, Ciphertext) = encapsulate::<Saber>(pk);
        let s2 = decapsulate::<Saber>(&ct, &sk);
        assert_eq!(&s1.sessionkey_cca, &s2.sessionkey_cca);
    }

    #[test]
    fn indcpa_impl() {
        let (pk, sk) = Saber::indcpa_kem_keypair();
        for _ in 0..100 {
            let noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
            let message_received = rand::random::<[u8; 32]>();
            let ciphertext = Saber::indcpa_kem_enc(&message_received, &noiseseed, &pk);
            let message_dec = Saber::indcpa_kem_dec(&sk, &ciphertext);
            assert_eq!(&message_dec[..], &message_received[..]);
        }
    }

    #[test]
    fn polyveccompressedbytes_value() {
        assert_eq!(POLYVECCOMPRESSEDBYTES + SEEDBYTES, INDCPA_PUBLICKEYBYTES);
    }

    #[test]
    fn bytes_cca_dec_value() {
        assert_eq!(CIPHERTEXTBYTES + RECONBYTES_KEM, BYTES_CCA_DEC);
    }

}
