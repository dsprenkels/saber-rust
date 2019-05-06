// TODO(dsprenkels) Currently implementing indcpa_kem_keypair

#![allow(unused)]

use core::ops::{Add, Mul, Shr, Sub};

use crate::params::*;
use crate::poly::Poly;
use crate::SaberImplementation;

/// Also known as `l`
pub const K: usize = 3;
pub const MU: usize = 8;
pub const DELTA: usize = 3;
pub const POLYVECCOMPRESSEDBYTES: usize = K * (N * 10) / 8;
pub const CIPHERTEXTBYTES: usize = POLYVECCOMPRESSEDBYTES;
pub const RECONBYTES: usize = DELTA * N / 8;
pub const RECONBYTES_KEM: usize = (DELTA + 1) * N / 8;
pub const INDCPA_PUBKEYBYTES: usize = 992;
pub const INDCPA_SECRETKEYBYTES: usize = 1248;
pub const PUBLICKEYBYTES: usize = 992;
pub const SECRETKEYBYTES: usize = 2304;
pub const BYTES_CCA_DEC: usize = 1088;
pub const MSG2POL_CONST: u8 = 9;

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

        // void ReconDataGen(uint16_t *vprime, unsigned char *rec_c);
        pub fn ReconDataGen(vprime: *mut Poly, rec_c: *mut u8);
    }
}

/// Vector is equivalent to the reference implementation's `polyvec` type.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vector([Poly; K]);

impl Add<Vector> for Vector {
    type Output = Vector;

    fn add(self, rhs: Self) -> Vector {
        let Vector(mut vec) = self;
        for i in 0..K {
            vec[i] = vec[i] + rhs.0[i];
        }
        Vector(vec)
    }
}

impl Add<u16> for Vector {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u16) -> Vector {
        let Vector(mut vec) = self;
        for i in 0..K {
            vec[i] = vec[i] + rhs;
        }
        Vector(vec)
    }
}

impl Mul<Vector> for Vector {
    type Output = Poly;

    /// As implemented by Algorithm 17
    fn mul(self, rhs: Self) -> Poly {
        let mut acc = Poly::new();
        for i in 0..K {
            acc = acc + (self.0[i] * rhs.0[i]);
        }
        acc
    }
}

impl Shr<u8> for Vector {
    type Output = Self;

    #[inline]
    fn shr(self, rhs: u8) -> Self {
        let Vector(mut vec) = self;
        for i in 0..K {
            vec[i] = vec[i] >> rhs;
        }
        Vector(vec)
    }
}

impl Vector {
    fn new() -> Self {
        Vector([Poly::new(); K])
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Matrix([Vector; K]);

impl Add<u16> for Matrix {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u16) -> Matrix {
        let Matrix(mut mat) = self;
        for i in 0..K {
            mat[i] = mat[i] + rhs;
        }
        Matrix(mat)
    }
}

impl Matrix {
    #[inline]
    fn new() -> Self {
        Matrix([Vector::new(); K])
    }

    /// As implemented by Algorithm 16
    #[inline]
    fn mul(self, rhs: Vector) -> Vector {
        let mut result = Vector::new();
        for i in 0..K {
            result.0[i] = self.0[i] * rhs;
        }
        result
    }

    /// As implemented by Algorithm 16
    #[inline]
    fn mul_transpose(self, rhs: Vector) -> Vector {
        let mut result = Vector::new();
        for i in 0..K {
            for j in 0..K {
                result.0[i] = result.0[i] + self.0[j].0[i] * rhs.0[j];
            }
        }
        result
    }
}

impl Shr<u8> for Matrix {
    type Output = Self;

    #[inline]
    fn shr(self, rhs: u8) -> Self {
        let Matrix(mut mat) = self;
        for i in 0..N {
            mat[i] = mat[i] >> rhs;
        }
        Matrix(mat)
    }
}

#[repr(C)]
pub struct PublicKey([u8; PUBLICKEYBYTES]);

#[repr(C)]
pub struct SecretKey([u8; SECRETKEYBYTES]);

/// Returns a tuple (public_key, secret_key), of PublicKey, SecretKey objects
fn indcpa_kem_keypair() -> (PublicKey, SecretKey) {
    let mut a = Matrix::new();
    let mut sk_vec = Vector::new();
    let mut pk_vec;
    let mut sk = SecretKey([0; SECRETKEYBYTES]);
    let mut pk = PublicKey([0; PUBLICKEYBYTES]);
    let mut seed = [0u8; SEEDBYTES];
    let mut noiseseed = [0u8; COINBYTES];

    unsafe {
        ffi::randombytes(seed.as_mut_ptr(), seed.len() as u64);
        ffi::shake128(
            seed.as_mut_ptr(),
            seed.len() as u64,
            seed.as_ptr(),
            seed.len() as u64,
        );
        ffi::randombytes(seed.as_mut_ptr(), seed.len() as u64);
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

// void indcpa_kem_enc(unsigned char *message_received, unsigned char *noiseseed, const unsigned char *pk, unsigned char *ciphertext)

fn indcpa_kem_enc(
    message_received: &[u8; KEYBYTES],
    noiseseed: &[u8; NOISE_SEEDBYTES],
    pk: &PublicKey,
) -> [u8; SECRETKEYBYTES] {
    let mut a = Matrix::new();
    let mut seed = [0; SEEDBYTES];
    let mut sk_vec1 = Vector::new();
    let mut pk_vec1: Vector;
    let mut ciphertext = [0; SECRETKEYBYTES];
    let mut public_key = PublicKey([0; PUBLICKEYBYTES]);
    let mut v1_vec: Vector = Vector::new();
    let pol_p: Poly;
    let mut m_p = Poly::new();
    let mut rec = [0; RECONBYTES_KEM];

    let (pk_vec, seed) = pk.0.split_at(POLYVECCOMPRESSEDBYTES);
    unsafe {
        ffi::GenMatrix(&mut a as *mut Matrix, seed.as_ptr());
        ffi::GenSecret(&mut sk_vec1 as *mut Vector, noiseseed.as_ptr());

        // Compute b' (called `res` in reference implementation)
        pk_vec1 = a.mul_transpose(sk_vec1);

        // Rounding of b' into v_p
        pk_vec1 = (pk_vec1 + 4) >> 3;

        // ct = POLVECp2BS(v_p)
        ffi::POLVECp2BS(ciphertext.as_mut_ptr(), &mut pk_vec1 as *mut Vector);

        // v' = BS2POLVECp(pk)
        ffi::BS2POLVECp(pk_vec.as_ptr(), &mut v1_vec as *mut Vector);

        // pol_p = VectorMul(v', s', p)
        pol_p = v1_vec * sk_vec1;

        // m_p = MSG2POL(m)
        for idx in 0..KEYBYTES {
            for idx2 in 0..8 {
                m_p.0[8 * idx + idx2] = ((message_received[idx] >> idx2) & 0x01) as u16;
            }
        }
        m_p = m_p << MSG2POL_CONST;

        // m_p = m_p + pol_p mod p
        m_p = m_p + pol_p;

        // rec = ReconDataGen(m_p)
        ffi::ReconDataGen(&mut m_p as *mut Poly, rec.as_mut_ptr());

        // CipherText_cpa = (rec || ct)
        ciphertext[POLYVECCOMPRESSEDBYTES..POLYVECCOMPRESSEDBYTES + RECONBYTES_KEM]
            .clone_from_slice(&rec);
    }
    ciphertext
}

pub struct Saber;

impl SaberImplementation for Saber {
    type Vector = [Poly; 3];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structs `LightSaber`, `Saber`, `FireSaber` exist to declare which
    /// set of parameters is to be used. As such, they hold no runtime data
    /// and their size in memory should be 0.
    #[test]
    fn saber_has_no_size() {
        assert_eq!(core::mem::size_of::<Saber>(), 0);
    }

    #[test]
    fn indcpa_reference() {
        let mut pk = PublicKey([0; PUBLICKEYBYTES]);
        let mut sk = SecretKey([0; SECRETKEYBYTES]);
        let mut noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
        let mut message_received = [b'A'; 32];
        let mut ciphertext = [b'B'; SECRETKEYBYTES];
        let mut message_dec = [b'C'; 32];

        unsafe {
            ffi::indcpa_kem_keypair(&mut pk as *mut PublicKey, &mut sk as *mut SecretKey);
            ciphertext = indcpa_kem_enc(&message_received, &noiseseed, &pk);
            ffi::indcpa_kem_dec(
                &mut sk as *mut SecretKey,
                ciphertext.as_ptr(),
                message_dec.as_mut_ptr(),
            );
        }
        assert_eq!(&message_dec[..], &message_received[..]);
    }

    #[test]
    fn indcpa_keypair() {
        let mut noiseseed = rand::random::<[u8; NOISE_SEEDBYTES]>();
        let mut message_received = [b'A'; 32];
        let mut ciphertext = [b'B'; SECRETKEYBYTES];
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
}
