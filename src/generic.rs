use rand_os::rand_core::RngCore;
use secret_integers::*;
use sha3::digest::{ExtendableOutput, Input, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512};

use crate::params::*;
use crate::poly::Poly;
use crate::*;

pub(crate) trait Vector<I: SaberImpl>: Clone + Default + Sized {
    #[must_use]
    fn polys(&self) -> &[Poly];
    #[must_use]
    fn polys_mut(&mut self) -> &mut [Poly];

    /// This function implements BS2POLVECq, as described in Algorithm 9
    fn from_bytes_mod_q(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), I::K * 13 * 256 / 8);
        let mut vec = Self::default();
        for (chunk, poly) in bytes
            .chunks_exact(13 * 256 / 8)
            .zip(vec.polys_mut().iter_mut())
        {
            *poly = Poly::from_bytes_13bit(chunk);
        }
        vec
    }

    /// This function implements BS2POLVECp, as described in Algorithm 13
    fn from_bytes_mod_p(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), I::K * 10 * 256 / 8);
        let mut vec = Self::default();
        for (chunk, poly) in bytes
            .chunks_exact(10 * 256 / 8)
            .zip(vec.polys_mut().iter_mut())
        {
            *poly = Poly::from_bytes_10bit(chunk);
        }
        vec
    }

    /// This function implements POLVECq2BS, as described in Algorithm 10
    fn read_mod_q(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), I::K * 13 * 256 / 8);
        for (poly, chunk) in self
            .polys()
            .iter()
            .zip(bytes.chunks_exact_mut(13 * 256 / 8))
        {
            poly.read_bytes_13bit(chunk);
        }
    }

    /// This function implements POLVECp2BS, as described in Algorithm 14
    fn read_mod_p(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), I::K * 10 * 256 / 8);
        for (poly, chunk) in self
            .polys()
            .iter()
            .zip(bytes.chunks_exact_mut(10 * 256 / 8))
        {
            poly.read_bytes_10bit(chunk);
        }
    }

    #[must_use]
    fn add_vec(mut self, rhs: &Self) -> Self {
        let polys = self.polys_mut();
        for (coeff, other) in polys.iter_mut().zip(rhs.polys().iter()) {
            *coeff = *coeff + *other;
        }
        self
    }

    #[must_use]
    fn add_u16(mut self, rhs: U16) -> Self {
        let polys = self.polys_mut();
        for poly in polys.iter_mut() {
            *poly = *poly + rhs;
        }
        self
    }

    #[must_use]
    fn shr(mut self, rhs: u32) -> Self {
        for poly in self.polys_mut().iter_mut() {
            *poly = *poly >> rhs;
        }
        self
    }

    /// As implemented by Algorithm 17
    #[must_use]
    fn mul(mut self, rhs: &Self) -> Poly {
        let polys = self.polys_mut();
        let mut acc = Poly::default();
        for (poly, other) in polys.iter_mut().zip(rhs.polys().iter()) {
            acc = acc + (*poly * *other);
        }
        acc
    }
}

pub(crate) trait Matrix<I: SaberImpl, V>: Clone + Default + Sized
where
    V: Vector<I> + Sized,
{
    fn vecs(&self) -> &[V];
    fn vecs_mut(&mut self) -> &mut [V];

    /// As implemented by Algorithm 16
    #[must_use]
    fn mul(self, rhs: &V) -> V {
        let mut result = V::default();
        let vecs = self.vecs();
        for (vec, result_vec) in vecs.iter().zip(result.polys_mut().iter_mut()) {
            *result_vec = vec.clone().mul(rhs);
        }
        result
    }

    /// As implemented by Algorithm 16
    #[must_use]
    fn mul_transpose(self, rhs: &V) -> V {
        let mut result = V::default();
        let vecs = self.vecs();
        for i in 0..vecs.len() {
            for j in 0..vecs.len() {
                result.polys_mut()[i] =
                    result.polys()[i] + self.vecs()[j].polys()[i] * rhs.polys()[j];
            }
        }
        result
    }
}

pub(crate) trait INDCPAPublicKey<I: SaberImpl>: Sized {
    fn new(vec: I::Vector, seed: [u8; SEEDBYTES]) -> Self;
    fn vec(&self) -> &I::Vector;
    fn seed(&self) -> &[u8; SEEDBYTES];

    fn to_bytes(&self) -> I::INDCPAPublicKeyBytes {
        let mut pk_newtype = I::INDCPAPublicKeyBytes::default();
        let bytes = pk_newtype.as_mut();
        let (pk, seed) = bytes.split_at_mut(I::POLYVECCOMPRESSEDBYTES);
        self.vec().read_mod_p(pk);
        seed.copy_from_slice(self.seed());
        pk_newtype
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), I::INDCPA_PUBLICKEYBYTES);
        let (vec_bytes, seed_bytes) = bytes.split_at(I::POLYVECCOMPRESSEDBYTES);
        let vec = I::Vector::from_bytes_mod_p(vec_bytes);
        let mut seed = [0; SEEDBYTES];
        seed.copy_from_slice(seed_bytes);
        INDCPAPublicKey::new(vec, seed)
    }
}

pub(crate) trait INDCPASecretKey<I: SaberImpl>: Sized {
    #[must_use]
    fn new(vec: I::Vector) -> Self;

    #[must_use]
    fn vec(&self) -> I::Vector;

    fn to_bytes(&self) -> I::INDCPASecretKeyBytes {
        let mut sk_newtype = I::INDCPASecretKeyBytes::default();
        let mut bytes = sk_newtype.as_mut();
        self.vec().read_mod_q(&mut bytes);
        sk_newtype
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != I::INDCPA_SECRETKEYBYTES {
            let err = crate::Error::BadLength {
                name: "bytes",
                actual: bytes.len(),
                expected: I::INDCPA_SECRETKEYBYTES,
            };
            return Err(err);
        }
        Ok(INDCPASecretKey::new(Vector::from_bytes_mod_q(bytes)))
    }
}

pub(crate) trait PublicKey<I: SaberImpl>: Sized {
    #[must_use]
    fn new(pk_cpa: I::INDCPAPublicKey) -> Self;

    #[must_use]
    fn pk_cpa(&self) -> &I::INDCPAPublicKey;

    #[must_use]
    fn to_bytes(&self) -> I::PublicKeyBytes;

    fn from_newtype(newtype: &I::PublicKeyBytes) -> Self {
        Self::from_bytes(newtype.as_ref()).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != I::PUBLIC_KEY_BYTES {
            let err = crate::Error::BadLength {
                name: "bytes",
                actual: bytes.len(),
                expected: I::PUBLIC_KEY_BYTES,
            };
            return Err(err);
        }
        let pk_cpa = I::INDCPAPublicKey::from_bytes(bytes);
        Ok(Self::new(pk_cpa))
    }
}

pub(crate) trait SecretKey<I: SaberImpl>: Clone + Sized {
    #[must_use]
    fn new(
        z: [u8; KEYBYTES],
        hash_pk: [u8; HASHBYTES],
        pk_cca: I::PublicKey,
        sk_cpa: I::INDCPASecretKey,
    ) -> Self;

    #[must_use]
    fn z(&self) -> &[u8; KEYBYTES];
    #[must_use]
    fn hash_pk(&self) -> &[u8; HASHBYTES];
    #[must_use]
    fn pk_cca(&self) -> &I::PublicKey;
    #[must_use]
    fn sk_cpa(&self) -> &I::INDCPASecretKey;

    fn unpack(
        &self,
    ) -> (
        &[u8; KEYBYTES],
        &[u8; HASHBYTES],
        &I::PublicKey,
        &I::INDCPASecretKey,
    ) {
        (self.z(), self.hash_pk(), self.pk_cca(), self.sk_cpa())
    }

    fn generate() -> I::SecretKey {
        keygen::<I>()
    }

    fn to_bytes(&self) -> I::SecretKeyBytes {
        let mut result = I::SecretKeyBytes::default();
        let bytes = result.as_mut();
        let (sk_cpa_bytes, rest) = bytes.split_at_mut(I::INDCPA_SECRETKEYBYTES);
        let (pk_cca_bytes, rest) = rest.split_at_mut(I::PUBLIC_KEY_BYTES);
        let (hash_pk_bytes, z_bytes) = rest.split_at_mut(HASHBYTES);

        sk_cpa_bytes.copy_from_slice(self.sk_cpa().to_bytes().as_ref());
        pk_cca_bytes.copy_from_slice(self.pk_cca().to_bytes().as_ref());
        hash_pk_bytes.copy_from_slice(self.hash_pk());
        z_bytes.copy_from_slice(self.z());
        result
    }

    fn from_newtype(newtype: &I::SecretKeyBytes) -> Self {
        Self::from_bytes(newtype.as_ref()).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != I::SECRET_KEY_BYTES {
            let err = crate::Error::BadLength {
                name: "bytes",
                actual: bytes.len(),
                expected: I::SECRET_KEY_BYTES,
            };
            return Err(err);
        }
        let (sk_cpa_bytes, rest) = bytes.split_at(I::INDCPA_SECRETKEYBYTES);
        let (pk_cca_bytes, rest) = rest.split_at(I::PUBLIC_KEY_BYTES);
        let (hash_pk_bytes, z_bytes) = rest.split_at(HASHBYTES);

        let sk_cpa = I::INDCPASecretKey::from_bytes(sk_cpa_bytes)?;
        let pk_cca = PublicKey::from_bytes(pk_cca_bytes)?;
        let mut hash_pk = [0; HASHBYTES];
        hash_pk.copy_from_slice(hash_pk_bytes);
        let mut z = [0; KEYBYTES];
        z.copy_from_slice(z_bytes);
        Ok(Self::new(z, hash_pk, pk_cca, sk_cpa))
    }
}

pub(crate) trait SaberImpl: Sized {
    const K: usize;
    const MU: usize;
    const RECON_SIZE: usize;

    // Constants added in this implementation
    // pub const MSG2POL_CONST: U8;

    const POLYVECCOMPRESSEDBYTES: usize;
    const INDCPA_PUBLICKEYBYTES: usize;
    const INDCPA_SECRETKEYBYTES: usize;

    // KEM parameters
    const PUBLIC_KEY_BYTES: usize;
    const SECRET_KEY_BYTES: usize;
    const BYTES_CCA_DEC: usize;

    /// Is called DELTA in the reference implemention
    const RECONBYTES_KEM: usize;

    type Vector: Vector<Self>;
    type Matrix: Matrix<Self, Self::Vector>;

    type SecretKey: SecretKey<Self>;
    type PublicKey: PublicKey<Self>;

    type PublicKeyBytes: AsRef<[u8]> + AsMut<[u8]> + Default;
    type SecretKeyBytes: AsRef<[u8]> + AsMut<[u8]> + Default;

    type INDCPAPublicKey: INDCPAPublicKey<Self>;
    type INDCPASecretKey: INDCPASecretKey<Self>;

    type INDCPAPublicKeyBytes: AsRef<[u8]> + AsMut<[u8]> + Default;
    type INDCPASecretKeyBytes: AsRef<[u8]> + AsMut<[u8]> + Default;

    type Ciphertext: AsRef<[u8]> + AsMut<[u8]> + Default;

    fn recon_poly_read_bytes_xbit(poly: Poly, buf: &mut [u8]);
    fn recon_poly_from_bytes_xbit(buf: &[u8]) -> Poly;
    fn cbd<T: XofReader>(xof: &mut T) -> Poly;
}

fn gen_secret<I: SaberImpl>(seed: &[u8]) -> I::Vector {
    debug_assert_eq!(seed.len(), NOISE_SEEDBYTES);
    let mut hasher = sha3::Shake128::default();
    hasher.input(seed);
    let mut xof = hasher.xof_result();

    let mut secret = I::Vector::default();
    for poly in secret.polys_mut().iter_mut() {
        *poly = I::cbd(&mut xof);
    }
    secret
}

pub(crate) fn load_littleendian(bytes: &[u8]) -> U64 {
    let mut r = 0.into();
    for (idx, b) in bytes.iter().enumerate() {
        r |= U64::from(U8::from(*b)) << (8 * idx as u32);
    }
    r
}

fn gen_matrix<I: SaberImpl>(seed: &[u8]) -> I::Matrix {
    debug_assert_eq!(seed.len(), SEEDBYTES);

    let mut hasher = sha3::Shake128::default();
    hasher.input(seed);
    let mut xof = hasher.xof_result();

    let mut matrix = I::Matrix::default();
    for vec in matrix.vecs_mut().iter_mut() {
        for poly in vec.polys_mut().iter_mut() {
            let mut buf = [0; 13 * N / 8];
            xof.read(&mut buf);
            *poly = Poly::from_bytes_13bit(&buf);
        }
    }
    matrix
}

/// This function implements ReconDataGen, as described in Algorithm 19
fn recon_data_gen<I: SaberImpl>(dest: &mut [u8], poly: &Poly) {
    debug_assert_eq!(dest.len(), I::RECONBYTES_KEM);
    let c = u32::from(EPS_P - I::RECON_SIZE as u8 - 1);
    I::recon_poly_read_bytes_xbit(poly.reduce(P) >> c, dest);
}

/// This function implement Recon, as described in Algorithm 20
fn recon<I: SaberImpl>(rec: &[u8], poly: &Poly) -> Poly {
    debug_assert_eq!(rec.len(), I::RECONBYTES_KEM);
    let c0 = u32::from(EPS_P - I::RECON_SIZE as u8 - 1);
    let c1 = (1 << (EPS_P - 2)) - (1 << (EPS_P - 2 - I::RECON_SIZE as u8)) as u16;

    let rec_poly = I::recon_poly_from_bytes_xbit(rec);
    let mut k_poly = Poly::default();
    let input_iter = rec_poly.coeffs.iter().zip(poly.coeffs.iter());
    for ((recbit, coeff), k) in input_iter.zip(k_poly.coeffs.iter_mut()) {
        let temp = *recbit << c0;
        let temp = *coeff - temp + c1.into();
        //                   temp
        // K_i = floor( --------------- )
        //              2^[log2(p) - 1]
        //
        // Observe that 2^[log2(p) - 1] is just (P/2), so K_i = 2*temp/P.
        // I.e. we calculate that by computing K_i ← temp >> (𝜖_p - 1).
        // *k |= (((temp >> (EPS_P - 1)) & 0x1) as U8) << idx;
        *k |= (temp >> (EPS_P - 1).into()) & 0x1.into();
    }
    k_poly
}

/// Returns a tuple (public_key, secret_key), of PublicKey, SecretKey objects
// C type in reference: void indcpa_kem_keypair(unsigned char *pk, unsigned char *sk);
pub(crate) fn indcpa_kem_keypair<I: SaberImpl>() -> (I::INDCPAPublicKey, I::INDCPASecretKey) {
    let mut rng = rand_os::OsRng::new().unwrap();
    let mut seed = [0; SEEDBYTES];
    rng.fill_bytes(&mut seed);
    let mut noiseseed = [0; COINBYTES];
    rng.fill_bytes(&mut noiseseed);
    indcpa_kem_keypair_deterministic::<I>(seed, noiseseed)
}

/// Deterministic part of indcpa_kem_keypair
///
/// The function has been split into two parts because of testing purposes.
pub(crate) fn indcpa_kem_keypair_deterministic<I: SaberImpl>(
    seed: [u8; SEEDBYTES],
    noiseseed: [u8; COINBYTES],
) -> (I::INDCPAPublicKey, I::INDCPASecretKey) {
    let a = generic::gen_matrix::<I>(&seed);
    let sk_vec = gen_secret::<I>(&noiseseed);

    // Compute b (called `res` in reference implementation)
    let pk_vec = a.mul(&sk_vec);

    // Rounding of b
    let pk_vec = pk_vec.add_u16(4.into()).shr(3);

    (
        I::INDCPAPublicKey::new(pk_vec, seed),
        I::INDCPASecretKey::new(sk_vec),
    )
}

// C type in reference: void indcpa_kem_enc(unsigned char *message_received, unsigned char *noiseseed, const unsigned char *pk, unsigned char *ciphertext)
pub(crate) fn indcpa_kem_enc<I: SaberImpl>(
    message_received: &[u8],
    noiseseed: &[u8],
    pk: &I::INDCPAPublicKey,
) -> I::Ciphertext {
    debug_assert_eq!(message_received.len(), KEYBYTES);
    debug_assert_eq!(noiseseed.len(), NOISE_SEEDBYTES);

    let mut ciphertext = I::Ciphertext::default();

    // CipherText_cpa = (rec || ct)
    let (ct, rec) = ciphertext.as_mut().split_at_mut(I::POLYVECCOMPRESSEDBYTES);

    // A = GenMatrix(seed_A)
    let a = generic::gen_matrix::<I>(pk.seed());

    // s' = GenSecret(seed_s')
    let sk_vec = gen_secret::<I>(&noiseseed);

    // Compute b' (called `res` in reference implementation)
    let pk_vec = a.mul_transpose(&sk_vec);

    // Rounding of b' into v_p
    let pk_vec = pk_vec.add_u16(4.into()).shr(3);

    // ct = POLVECp2BS(v_p)
    pk_vec.read_mod_p(ct);

    // v' = BS2POLVECp(pk)
    let v1_vec = pk.vec();

    // pol_p = VectorMul(v', s', p)
    let pol_p = v1_vec.clone().mul(&sk_vec);

    // m_p = MSG2POL(m)
    let mut m_p = Poly::from_msg(message_received);

    // m_p = m_p + pol_p mod p
    m_p = m_p + pol_p;

    // rec = ReconDataGen(m_p)
    recon_data_gen::<I>(rec, &m_p);

    ciphertext
}

// C type in reference: void indcpa_kem_dec(const unsigned char *sk, const unsigned char *ciphertext, unsigned char message_dec[])
pub(crate) fn indcpa_kem_dec<I: SaberImpl>(
    sk: &I::INDCPASecretKey,
    ciphertext: &I::Ciphertext,
) -> [u8; MESSAGEBYTES] {
    // Extract (rec || ct) = CipherText
    let (ct, _) = ciphertext.as_ref().split_at(I::POLYVECCOMPRESSEDBYTES);
    let rec = &ciphertext.as_ref()[I::POLYVECCOMPRESSEDBYTES..];

    // Unpack the secret key from the full SecretKey buffer
    let sk_vec = sk.vec();

    // b = BS2BOLVECp(ct)
    let b_vec = I::Vector::from_bytes_mod_p(ct);

    // v' = VectorMul(b, s, p)
    let v1 = b_vec.mul(&sk_vec);

    // m' = Recon(rec, v')
    let message_dec_unpacked = recon::<I>(&rec, &v1);

    // m = POL2MSG(m')
    let mut message_dec = [0; MESSAGEBYTES];
    message_dec_unpacked.read_bytes_msg(&mut message_dec);
    message_dec
}

__byte_array_newtype!(
    pub SharedSecret, KEYBYTES, [u8; KEYBYTES]
);

// ---------- KEM functions ----------

/// This function implements Saber.KEM.KeyGen, as described in Algorithm 26
pub(crate) fn keygen<I: SaberImpl>() -> I::SecretKey {
    let (pk_cpa, sk_cpa) = indcpa_kem_keypair::<I>();
    let mut hash_pk = [0; HASHBYTES];
    let pk_cpa_bytes = pk_cpa.to_bytes();
    let hash_digest = Sha3_256::digest(pk_cpa_bytes.as_ref());
    hash_pk.copy_from_slice(hash_digest.as_slice());
    let mut z = [0; KEYBYTES];
    rand_os::OsRng::new().unwrap().fill_bytes(&mut z);
    I::SecretKey::new(z, hash_pk, I::PublicKey::new(pk_cpa), sk_cpa)
}

/// This function implements Saber.KEM.Encaps, as described in Algorithm 27
pub(crate) fn encapsulate<I: SaberImpl>(pk_cca: &I::PublicKey) -> (SharedSecret, I::Ciphertext) {
    let mut m = [0; KEYBYTES];
    rand_os::OsRng::new().unwrap().fill_bytes(&mut m);
    let hash_pk = Sha3_256::digest(&pk_cca.to_bytes().as_ref());
    let mut hasher = Sha3_512::default();
    sha3::digest::Input::input(&mut hasher, hash_pk);
    sha3::digest::Input::input(&mut hasher, m);
    let mut kr_digest = hasher.result();
    let kr = kr_digest.as_mut_slice();
    let r = &mut kr[0..KEYBYTES];
    let ciphertext_cca = indcpa_kem_enc::<I>(&m, r, pk_cca.pk_cpa());
    r.copy_from_slice(Sha3_256::digest(ciphertext_cca.as_ref()).as_slice());
    let mut sessionkey_cca = [0; KEYBYTES];
    (&mut sessionkey_cca).copy_from_slice(Sha3_256::digest(kr).as_slice());
    (SharedSecret::from(sessionkey_cca), ciphertext_cca)
}

/// This function implements Saber.KEM.Decaps, as described in Algorithm 28
pub(crate) fn decapsulate<I: SaberImpl>(ct: &I::Ciphertext, sk: &I::SecretKey) -> SharedSecret {
    #![allow(clippy::many_single_char_names)]

    let (z, hash_pk, pk_cca, sk_cpa) = sk.unpack();
    let pk_cpa = pk_cca.pk_cpa();

    let m = indcpa_kem_dec::<I>(&sk_cpa, &ct);

    let mut hasher = Sha3_512::default();
    sha3::digest::Input::input(&mut hasher, hash_pk);
    sha3::digest::Input::input(&mut hasher, m);
    let mut kr_digest = hasher.result();
    let kr = kr_digest.as_mut_slice();
    let (r, k) = kr.split_at_mut(KEYBYTES);

    let ciphertext_cca_check = indcpa_kem_enc::<I>(&m, r, &pk_cpa);
    let fail = U8::from(0xFF) ^ bytes_eq_mask(ciphertext_cca_check.as_ref(), ct.as_ref());
    r.copy_from_slice(Sha3_256::digest(ciphertext_cca_check.as_ref()).as_slice());

    let mut hasher = Sha3_256::default();
    for (rb, zb) in r.iter().zip(z.iter()) {
        let b = (U8::from(*rb) & !fail) | (U8::from(*zb) & fail);
        sha3::digest::Input::input(&mut hasher, [b.declassify()]);
    }
    sha3::digest::Input::input(&mut hasher, k);

    let mut sessionkey_cca = [0; KEYBYTES];
    sessionkey_cca.copy_from_slice(hasher.result().as_slice());
    SharedSecret::from(sessionkey_cca)
}

/// This function implements Verify, with some tweaks.
///
/// Returns
///   | buf1 == buf2 = 0xFF
///   | otherwise    = 0x00
fn bytes_eq_mask(buf1: &[u8], buf2: &[u8]) -> U8 {
    debug_assert_eq!(buf1.len(), buf2.len());
    let mut acc = U8::from(0xFF);
    for (b1, b2) in buf1.iter().zip(buf2.iter()) {
        acc &= u8_eq_mask(U8::from(*b1), U8::from(*b2));
    }
    acc
}

/// Compare two U8's for equality
///
/// Return
///   | buf1 == buf2 = 0xFF
///   | otherwise    = 0x00
///
/// This function is based on the [`u64_eq_mask`] function from the Curve25519 HACL implementation
/// in Wireguard.
///
/// We use this function because it seems that the `U8::comp_eq` function from the
/// `secret_integers` crate has a bug. See for yourself:
///
/// ```should_fail
/// use secret_integers::U8;
///
/// let a = U8::from(3);
/// let b = U8::from(3);
/// let eq = U8::comp_eq(a, b);
///
/// // This equality fails:
/// assert_eq!(eq.declassify(), 0xFF);
/// ```
///
/// [`u64_eq_mask`]: https://git.zx2c4.com/WireGuard/commit/src/crypto/curve25519-hacl64.h?id=2e60bb395c1f589a398ec606d611132ef9ef764b
fn u8_eq_mask(x: U8, y: U8) -> U8 {
    let mut z = x ^ y;
    z |= -z;
    (z >> 7) - 1.into()
}

pub(crate) fn declassify_bytes(dest: &mut [u8], src: &[U8]) {
    debug_assert_eq!(dest.len(), src.len());
    for (i, o) in src.iter().zip(dest.iter_mut()) {
        *o = i.declassify();
    }
}
