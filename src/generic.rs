use crate::poly::Poly;
use rand::random;
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512};

use crate::params::*;
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
    #[inline]
    fn add_vec(mut self, rhs: &Self) -> Self {
        let polys = self.polys_mut();
        for (coeff, other) in polys.iter_mut().zip(rhs.polys().iter()) {
            *coeff = *coeff + *other;
        }
        self
    }

    #[must_use]
    #[inline]
    fn add_u16(mut self, rhs: u16) -> Self {
        let polys = self.polys_mut();
        for poly in polys.iter_mut() {
            *poly = *poly + rhs;
        }
        self
    }

    #[must_use]
    #[inline]
    fn shr(mut self, rhs: u8) -> Self {
        for poly in self.polys_mut().iter_mut() {
            *poly = *poly >> rhs;
        }
        self
    }

    /// As implemented by Algorithm 17
    #[must_use]
    #[inline]
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
    #[inline]
    fn mul(self, rhs: &V) -> V {
        let mut result = V::default();
        let vecs = self.vecs();
        for (vec, result_vec) in vecs.iter().zip(result.polys_mut().iter_mut()) {
            *result_vec = vec.clone().mul(rhs);
        }
        result
    }

    /// As implemented by Algorithm 16
    #[inline]
    fn mul_transpose(self, rhs: &V) -> V {
        // TODO(dsprenkels) Use iterators instead of vecs.len() if possible
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
    fn new(vec: I::Vector) -> Self;

    fn vec(&self) -> I::Vector;

    fn to_bytes(&self) -> I::INDCPASecretKeyBytes {
        let mut sk_newtype = I::INDCPASecretKeyBytes::default();
        let mut bytes = sk_newtype.as_mut();
        self.vec().read_mod_q(&mut bytes);
        sk_newtype
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != I::INDCPA_SECRETKEYBYTES {
            let err = crate::Error::BadLengthError {
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
    fn new(pk_cpa: I::INDCPAPublicKey) -> Self;

    fn pk_cpa(&self) -> &I::INDCPAPublicKey;

    fn to_bytes(&self) -> I::PublicKeyBytes;

    fn from_newtype(newtype: &I::PublicKeyBytes) -> Self {
        Self::from_bytes(newtype.as_ref()).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        if bytes.len() != I::PUBLIC_KEY_BYTES {
            let err = crate::Error::BadLengthError {
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
    fn new(
        z: [u8; KEYBYTES],
        hash_pk: [u8; HASHBYTES],
        pk_cca: I::PublicKey,
        sk_cpa: I::INDCPASecretKey,
    ) -> Self;

    fn z(&self) -> &[u8; KEYBYTES];
    fn hash_pk(&self) -> &[u8; HASHBYTES];
    fn pk_cca(&self) -> &I::PublicKey;
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
            let err = crate::Error::BadLengthError {
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
    // pub const MSG2POL_CONST: u8;

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

    fn gen_secret(seed: &[u8]) -> Self::Vector;
}

pub(crate) fn gen_matrix<I: SaberImpl>(seed: &[u8]) -> I::Matrix {
    use sha3::digest::Input;
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
pub(crate) fn recon_data_gen<I: SaberImpl>(dest: &mut [u8], poly: &Poly) {
    debug_assert_eq!(dest.len(), I::RECONBYTES_KEM);
    let c = EPS_P - (I::RECON_SIZE as u8) - 1;
    (poly.reduce(P) >> c).read_bytes_4bit(dest);
}

/// This function implement Recon, as described in Algorithm 20
pub(crate) fn recon<I: SaberImpl>(rec: &[u8], poly: &Poly) -> Poly {
    debug_assert_eq!(rec.len(), I::RECONBYTES_KEM);
    let c0: u8 = EPS_P - I::RECON_SIZE as u8 - 1;
    let c1: u16 = (1 << (EPS_P - 2)) - (1 << (EPS_P - 2 - I::RECON_SIZE as u8));

    let rec_poly = Poly::from_bytes_4bit(rec);
    let mut k_poly = Poly::default();
    let input_iter = rec_poly.coeffs.iter().zip(poly.coeffs.iter());
    for ((recbit, coeff), k) in input_iter.zip(k_poly.coeffs.iter_mut()) {
        let temp = recbit << c0;
        let temp = coeff.wrapping_sub(temp).wrapping_add(c1);
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

/// Returns a tuple (public_key, secret_key), of PublicKey, SecretKey objects
// C type in reference: void indcpa_kem_keypair(unsigned char *pk, unsigned char *sk);
pub(crate) fn indcpa_kem_keypair<I: SaberImpl>() -> (I::INDCPAPublicKey, I::INDCPASecretKey) {
    let seed: [u8; SEEDBYTES] = rand::random();
    let noiseseed: [u8; COINBYTES] = rand::random();

    let a = generic::gen_matrix::<I>(&seed);
    let sk_vec = I::gen_secret(&noiseseed);

    // Compute b (called `res` in reference implementation)
    let pk_vec = a.mul(&sk_vec);

    // Rounding of b
    let pk_vec = pk_vec.add_u16(4).shr(3);

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
    let sk_vec = I::gen_secret(&noiseseed);

    // Compute b' (called `res` in reference implementation)
    let pk_vec = a.mul_transpose(&sk_vec);

    // Rounding of b' into v_p
    let pk_vec = pk_vec.add_u16(4).shr(3);

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
    let z: [u8; KEYBYTES] = random();
    let sk_cca = I::SecretKey::new(z, hash_pk, I::PublicKey::new(pk_cpa), sk_cpa);
    sk_cca
}

/// This function implements Saber.KEM.Encaps, as described in Algorithm 27
pub(crate) fn encapsulate<I: SaberImpl>(pk_cca: &I::PublicKey) -> (SharedSecret, I::Ciphertext) {
    let m: [u8; KEYBYTES] = random();
    let hash_pk = Sha3_256::digest(&pk_cca.to_bytes().as_ref());
    let mut hasher = Sha3_512::default();
    hasher.input(hash_pk);
    hasher.input(m);
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
    let (z, hash_pk, pk_cca, sk_cpa) = sk.unpack();
    let pk_cpa = pk_cca.pk_cpa();

    let m = indcpa_kem_dec::<I>(&sk_cpa, &ct);
    let mut hasher = Sha3_512::default();
    hasher.input(hash_pk);
    hasher.input(m);
    let mut kr_digest = hasher.result();
    let kr = kr_digest.as_mut_slice();
    let (r, k) = kr.split_at_mut(KEYBYTES);

    let ciphertext_cca_check = indcpa_kem_enc::<I>(&m, r, &pk_cpa);
    let fail = !compare_ct(ciphertext_cca_check.as_ref(), ct.as_ref());
    r.copy_from_slice(Sha3_256::digest(ciphertext_cca_check.as_ref()).as_slice());

    let mut hasher = Sha3_256::default();
    for (rb, zb) in r.iter().zip(z.iter()) {
        let mask = (fail as u8).wrapping_neg();
        let b = (rb & !mask) | (zb & mask);
        hasher.input([b]);
    }
    hasher.input(k);

    let mut sessionkey_cca = [0; KEYBYTES];
    sessionkey_cca.copy_from_slice(hasher.result().as_slice());
    SharedSecret::from(sessionkey_cca)
}

/// This function implements Verify, with some tweaks.
///
/// The design document ambiguously specifies which of `true` and `false` mean that the strings
/// were actually equal. The reference implementation return 0, when the strings are equal.
/// However, this is Rust, and we follow conventions. So this function returns true if the strings
/// are equal, otherwise false. I.e.
fn compare_ct(buf1: &[u8], buf2: &[u8]) -> bool {
    if buf1.len() != buf2.len() {
        return false;
    }
    let mut acc = true;
    for (b1, b2) in buf1.iter().zip(buf2.iter()) {
        acc |= b1 == b2;
    }
    acc
}
