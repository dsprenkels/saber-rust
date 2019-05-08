#![allow(unused)]

use core::ops::{Add, Mul, Shr, Sub};

use sha3::digest::{ExtendableOutput, Input, XofReader};

use crate::params::*;
use crate::poly::Poly;

/// Also known as `l`
pub const K: usize = 3;

pub const MU: usize = 8;
/// Is called DELTA in the reference implemention
pub const RECON_SIZE: usize = 3;
pub const POLYVECCOMPRESSEDBYTES: usize = K * (N * 10) / 8;
pub const CIPHERTEXTBYTES: usize = POLYVECCOMPRESSEDBYTES;
pub const RECONBYTES: usize = RECON_SIZE * N / 8;
pub const RECONBYTES_KEM: usize = (RECON_SIZE + 1) * N / 8;
pub const INDCPA_PUBKEYBYTES: usize = 992;
pub const INDCPA_SECRETKEYBYTES: usize = 1248;
pub const PUBLICKEYBYTES: usize = 992;
pub const SECRETKEYBYTES: usize = 2304;
pub const BYTES_CCA_DEC: usize = 1088;

mod ffi {
    use super::*;

    extern "C" {
        pub fn indcpa_kem_keypair(pk: *mut PublicKey, sk: *mut SecretKey);
        pub fn indcpa_kem_enc(
            message_received: *mut u8,
            noiseseed: *mut u8,
            pk: *const PublicKey,
            ciphertext: *mut u8,
        );
        pub fn indcpa_kem_dec(sk: *const SecretKey, ciphertext: *const u8, message_dec: *mut u8);
        pub fn randombytes(output: *mut u8, len: u64);
        pub fn shake128(output: *mut u8, outlen: u64, input: *const u8, inlen: u64);

        // GenMatrix(polyvec *a, const unsigned char *seed)
        pub fn GenMatrix(a: *mut Matrix, seed: *const u8);

        // GenSecret(uint16_t r[SABER_K][SABER_N],const unsigned char *seed)
        pub fn GenSecret(s: *mut Vector, seed: *const u8);

        // void MatrixVectorMul(polyvec *a, uint16_t skpv[SABER_K][SABER_N], uint16_t res[SABER_K][SABER_N], uint16_t mod, int16_t transpose);
        pub fn MatrixVectorMul(
            a: *mut Matrix,
            skpv: *mut Vector,
            result: *mut Vector,
            modulus: u16,
            transpose: i16,
        );

        // void POLVECq2BS(uint8_t *sk,  uint16_t skpv[SABER_K][SABER_N]);
        pub fn POLVECq2BS(sk: *mut u8, skpv: *mut Vector);

        // void POLVECp2BS(uint8_t *pk,  uint16_t skpv[SABER_K][SABER_N]);
        pub fn POLVECp2BS(pk: *mut u8, skpv: *mut Vector);

        // void BS2POLVECp(const unsigned char *pk, uint16_t data[SABER_K][SABER_N]);
        pub fn BS2POLVECp(pk: *const u8, data: *mut Vector);

        // void BS2POLVECq(const unsigned char *sk,  uint16_t skpv[SABER_K][SABER_N]);
        pub fn BS2POLVECq(sk: *const u8, skpv: *mut Vector);

        // void POL2MSG(uint16_t *message_dec_unpacked, unsigned char *message_dec);
        pub fn POL2MSG(message_dec_unpacked: *mut Poly, message_dec: *mut u8);

        // void ReconDataGen(uint16_t *vprime, unsigned char *rec_c);
        pub fn ReconDataGen(vprime: *mut Poly, rec_c: *mut u8);

        // void Recon(uint16_t *recon_data,unsigned char *recon_ar,uint16_t *message_dec_unpacked);
        pub fn Recon(recon_data: *mut Poly, recon_ar: *mut u8, message_dec_unpacked: *mut Poly);

        // void BS2POLq(const unsigned char *bytes, uint16_t data[SABER_N]);
        pub fn BS2POLq(bytes: *const u8, data: *mut Poly);
    }
}

/// Vector is equivalent to the reference implementation's `polyvec` type.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Vector {
    polys: [Poly; K],
}

impl Add<Vector> for Vector {
    type Output = Vector;

    fn add(mut self, rhs: Self) -> Vector {
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
    fn add(mut self, rhs: u16) -> Vector {
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
    fn mul(mut self, rhs: Self) -> Poly {
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

impl Vector {
    /// This function implements BS2POLVECq, as described in Algorithm 9
    pub fn from_bytes_mod_q(bs: &[u8]) -> Self {
        debug_assert_eq!(bs.len(), K * 13 * 256 / 8);
        let mut vec = Vector::default();
        for (bs_chunk, poly) in bs.chunks_exact(13 * 256 / 8).zip(vec.polys.iter_mut()) {
            *poly = Poly::from_bytes_13bit(bs_chunk);
        }
        vec
    }

    /// This function implements BS2POLVECp, as described in Algorithm 13
    pub fn from_bytes_mod_p(bs: &[u8]) -> Self {
        debug_assert_eq!(bs.len(), K * 10 * 256 / 8);
        let mut vec = Vector::default();
        for (bs_chunk, poly) in bs.chunks_exact(10 * 256 / 8).zip(vec.polys.iter_mut()) {
            *poly = Poly::from_bytes_10bit(bs_chunk);
        }
        vec
    }

    /// This function implements POLVECp2BS, as described in Algorithm 14
    pub fn read_mod_p(&self, bs: &mut [u8]) {
        debug_assert_eq!(bs.len(), K * 10 * 256 / 8);
        for (poly, bs_chunk) in self.polys.iter().zip(bs.chunks_exact_mut(10 * 256 / 8)) {
            poly.read_bytes_10bit(bs_chunk);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Matrix {
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
    fn mul_transpose(mut self, rhs: Vector) -> Vector {
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
    fn shr(mut self, rhs: u8) -> Self {
        let Matrix { mut vecs } = self;
        for vec in vecs.iter_mut() {
            *vec = *vec >> rhs;
        }
        Matrix { vecs }
    }
}

#[repr(C)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

#[repr(C)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

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

fn gen_secret(seed: &[u8; NOISE_SEEDBYTES]) -> Vector {
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
        *k |= ((temp >> (EPS_P - 1)) & 0x1);
    }
    k_poly
}

/// Returns a tuple (public_key, secret_key), of PublicKey, SecretKey objects
// C type in reference: void indcpa_kem_keypair(unsigned char *pk, unsigned char *sk);
pub fn indcpa_kem_keypair() -> (PublicKey, SecretKey) {
    let mut a = Matrix::default();
    let mut sk_vec = Vector::default();
    let mut pk_vec;
    let mut sk = SecretKey([0; SECRETKEYBYTES]);
    let mut pk = PublicKey([0; PUBLICKEYBYTES]);
    let mut seed: [u8; SEEDBYTES] = rand::random();
    let mut noiseseed: [u8; COINBYTES] = rand::random();

    unsafe {
        ffi::GenMatrix(&mut a as *mut Matrix, seed.as_ptr());
        ffi::GenSecret(&mut sk_vec as *mut Vector, noiseseed.as_ptr());

        // Compute b (called `res` in reference implementation)
        pk_vec = a.mul(sk_vec);

        // Rounding of b
        pk_vec = (pk_vec + 4) >> 3;

        // Save the secret and public vectors
        ffi::POLVECq2BS(sk.0.as_mut_ptr(), &mut sk_vec as *mut Vector);
        ffi::POLVECp2BS(pk.0.as_mut_ptr(), &mut pk_vec as *mut Vector);
        (&mut pk.0[POLYVECCOMPRESSEDBYTES..]).copy_from_slice(&seed[..]);
    }
    (pk, sk)
}

// C type in reference: void indcpa_kem_enc(unsigned char *message_received, unsigned char *noiseseed, const unsigned char *pk, unsigned char *ciphertext)
pub fn indcpa_kem_enc(
    message_received: &[u8; KEYBYTES],
    noiseseed: &[u8; NOISE_SEEDBYTES],
    pk: &PublicKey,
) -> [u8; BYTES_CCA_DEC] {
    let mut ciphertext = [0; BYTES_CCA_DEC];

    // CipherText_cpa = (rec || ct)
    let (ct, rec) = ciphertext.split_at_mut(POLYVECCOMPRESSEDBYTES);

    // Extract pk and seed_A from PublicKey_cpa = (pk || seed_A)
    let (pk, seed) = pk.0.split_at(POLYVECCOMPRESSEDBYTES);

    // A = GenMatrix(seed_A)
    let a = gen_matrix(seed);

    // s' = GenSecret(seed_s')
    let sk_vec = gen_secret(&noiseseed);

    // Compute b' (called `res` in reference implementation)
    let mut pk_vec = a.mul_transpose(sk_vec);

    // Rounding of b' into v_p
    pk_vec = (pk_vec + 4) >> 3;

    // ct = POLVECp2BS(v_p)
    pk_vec.read_mod_p(ct);

    // v' = BS2POLVECp(pk)
    let v1_vec = Vector::from_bytes_mod_p(pk);

    // pol_p = VectorMul(v', s', p)
    let pol_p = v1_vec * sk_vec;

    // m_p = MSG2POL(m)
    let mut m_p = Poly::from_msg(message_received);

    // m_p = m_p + pol_p mod p
    m_p = m_p + pol_p;

    // rec = ReconDataGen(m_p)
    recon_data_gen(rec, &m_p);

    ciphertext
}

// C type in reference: void indcpa_kem_dec(const unsigned char *sk, const unsigned char *ciphertext, unsigned char message_dec[])
pub fn indcpa_kem_dec(full_sk: &SecretKey, ciphertext: &[u8; BYTES_CCA_DEC]) -> [u8; MESSAGEBYTES] {
    let mut b_vec = Vector::default();
    let mut message_dec_unpacked = Poly::default();
    let mut message_dec = [0; MESSAGEBYTES];

    // Extract (rec || ct) = CipherText
    let (ct, _) = ciphertext.split_at(POLYVECCOMPRESSEDBYTES);
    let mut rec = [0; RECONBYTES_KEM];
    rec.copy_from_slice(&ciphertext[POLYVECCOMPRESSEDBYTES..]);

    // Unpack the secret key from the full SecretKey buffer
    let (sk, _) = full_sk.0.split_at(INDCPA_SECRETKEYBYTES);

    // s = BS2POLVECq(SecretKey_cpa)
    let sk_vec = Vector::from_bytes_mod_q(sk);

    // b = BS2BOLVECp(ct)
    let b_vec = Vector::from_bytes_mod_p(ct);

    // v' = VectorMul(b, s, p)
    let mut v1 = b_vec * sk_vec;

    // m' = Recon(rec, v')
    message_dec_unpacked = recon(&rec, &v1);

    // m = POL2MSG(m')
    message_dec_unpacked.read_bytes_msg(&mut message_dec);
    message_dec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indcpa_impl() {
        let (pk, sk) = indcpa_kem_keypair();
        for _ in 0..100 {
            let mut noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
            let mut message_received = rand::random::<[u8; 32]>();
            let ciphertext = indcpa_kem_enc(&message_received, &noiseseed, &pk);
            let message_dec = indcpa_kem_dec(&sk, &ciphertext);
            assert_eq!(&message_dec[..], &message_received[..]);
        }
    }

    #[test]
    fn indcpa_reference() {
        let mut pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut sk = SecretKey([0; SECRETKEYBYTES]);

        for _ in 0..100 {
            let mut noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
            let mut message_received = rand::random::<[u8; MESSAGEBYTES]>();
            let mut ciphertext = [0; BYTES_CCA_DEC];
            let mut message_dec = [0; MESSAGEBYTES];
            unsafe {
                ffi::indcpa_kem_keypair(&mut pk as *mut PublicKey, &mut sk as *mut SecretKey);
                ffi::indcpa_kem_enc(
                    message_received.as_mut_ptr(),
                    noiseseed.as_mut_ptr(),
                    &pk as *const PublicKey,
                    ciphertext.as_mut_ptr(),
                );
                ffi::indcpa_kem_dec(
                    &mut sk as *mut SecretKey,
                    ciphertext.as_ptr(),
                    message_dec.as_mut_ptr(),
                );
            }
            assert_eq!(&message_dec[..], &message_received[..]);
        }
    }

    #[test]
    fn indcpa_keypair() {
        let mut noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
        let mut message_received = [b'A'; 32];
        let mut ciphertext = [b'B'; BYTES_CCA_DEC];
        let mut message_dec = [b'C'; 32];

        let (mut pk, mut sk) = indcpa_kem_keypair();
        unsafe {
            ffi::indcpa_kem_enc(
                message_received.as_mut_ptr(),
                noiseseed.as_mut_ptr(),
                &pk as *const PublicKey,
                ciphertext.as_mut_ptr(),
            );
            ffi::indcpa_kem_dec(
                &sk as *const SecretKey,
                ciphertext.as_ptr(),
                message_dec.as_mut_ptr(),
            );
        }
        assert_eq!(&message_dec[..], &message_received[..]);
    }

    #[test]
    fn polyveccompressedbytes_value() {
        assert_eq!(POLYVECCOMPRESSEDBYTES + SEEDBYTES, PUBLICKEYBYTES);
    }

    #[test]
    fn bytes_cca_dec_value() {
        assert_eq!(CIPHERTEXTBYTES + RECONBYTES_KEM, BYTES_CCA_DEC);
    }
}
