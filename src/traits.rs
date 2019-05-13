use rand::random;
use sha3::{Digest, Sha3_256, Sha3_512};

use crate::common::*;
use crate::Error as SaberError;

pub trait Vector<I: SaberImpl> {
    fn from_bytes_mod_q(bytes: &[u8]) -> Self;
    fn from_bytes_mod_p(bytes: &[u8]) -> Self;
    fn read_mod_q(&self, bytes: &mut [u8]);
    fn read_mod_p(&self, bytes: &mut [u8]);
}

pub trait Matrix<I: SaberImpl> {}

pub trait INDCPAPublicKey<I: SaberImpl>: Sized {
    fn new(vec: I::Vector, seed: [u8; SEEDBYTES]) -> Self;

    fn to_bytes(&self) -> I::INDCPAPublicKeyBytes;

    fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), I::INDCPA_PUBLICKEYBYTES);
        let (vec_bytes, seed_bytes) = bytes.split_at(I::POLYVECCOMPRESSEDBYTES);
        let vec = I::Vector::from_bytes_mod_p(vec_bytes);
        let mut seed = [0; SEEDBYTES];
        seed.copy_from_slice(seed_bytes);
        INDCPAPublicKey::new(vec, seed)
    }
}

pub trait INDCPASecretKey<I: SaberImpl>: Sized {}

pub trait PublicKey<I: SaberImpl>: Sized {
    fn new(pk_cpa: I::INDCPAPublicKey) -> Self;

    fn pk_cpa(&self) -> &I::INDCPAPublicKey;

    fn to_bytes(&self) -> I::PublicKeyBytes;

    fn from_bytes(bytes: &[u8]) -> Result<Self, SaberError> {
        if bytes.len() != I::PUBLIC_KEY_BYTES {
            let err = SaberError::BadLengthError {
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

pub trait SecretKey<I: SaberImpl>: Sized {
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

    fn to_bytes(&self) -> I::SecretKeyBytes;

    fn from_bytes(bytes: &[u8]) -> Result<Self, SaberError> {
        if bytes.len() != I::SECRET_KEY_BYTES {
            let err = SaberError::BadLengthError {
                name: "bytes",
                actual: bytes.len(),
                expected: I::SECRET_KEY_BYTES,
            };
            return Err(err);
        }
        unimplemented!()
    }
}

pub trait SaberImpl: Sized {
    // Constants added in this implementation
    const MSG2POL_CONST: u8;

    const POLYVECCOMPRESSEDBYTES: usize;

    const PUBLIC_KEY_BYTES: usize;
    const SECRET_KEY_BYTES: usize;
    const INDCPA_PUBLICKEYBYTES: usize;
    const INDCPA_SECRETKEYBYTES: usize;

    type Vector: Vector<Self>;
    type Matrix: Matrix<Self>;

    type SecretKey: SecretKey<Self>;
    type PublicKey: PublicKey<Self>;

    type PublicKeyBytes: AsRef<[u8]>;
    type SecretKeyBytes: AsRef<[u8]>;

    type INDCPAPublicKey: INDCPAPublicKey<Self>;
    type INDCPASecretKey: INDCPASecretKey<Self>;

    type INDCPAPublicKeyBytes: AsRef<[u8]>;
    type INDCPASecretKeyBytes: AsRef<[u8]>;

    type Ciphertext: AsRef<[u8]>;

    fn indcpa_kem_keypair() -> (Self::INDCPAPublicKey, Self::INDCPASecretKey);
    fn indcpa_kem_enc(
        message_received: &[u8],
        noiseseed: &[u8],
        pk: &Self::INDCPAPublicKey,
    ) -> Self::Ciphertext;
    fn indcpa_kem_dec(
        sk: &Self::INDCPASecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> [u8; MESSAGEBYTES];
}

/// This function implements Saber.KEM.KeyGen, as described in Algorithm 26
pub fn keygen<I: SaberImpl>() -> I::SecretKey {
    let (pk_cpa, sk_cpa) = I::indcpa_kem_keypair();
    let mut hash_pk = [0; HASHBYTES];
    let pk_cpa_bytes = pk_cpa.to_bytes();
    let hash_digest = Sha3_256::digest(pk_cpa_bytes.as_ref());
    hash_pk.copy_from_slice(hash_digest.as_slice());
    let z: [u8; KEYBYTES] = random();
    let sk_cca = I::SecretKey::new(z, hash_pk, I::PublicKey::new(pk_cpa), sk_cpa);
    sk_cca
}

/// This function implements Saber.KEM.Encaps, as described in Algorithm 27
pub fn encapsulate<I: SaberImpl>(pk_cca: &I::PublicKey) -> (SharedSecret, I::Ciphertext) {
    let m: [u8; KEYBYTES] = random();
    let hash_pk = Sha3_256::digest(&pk_cca.to_bytes().as_ref());
    let mut hasher = Sha3_512::default();
    hasher.input(hash_pk);
    hasher.input(m);
    let mut kr_digest = hasher.result();
    let kr = kr_digest.as_mut_slice();
    let r = &mut kr[0..KEYBYTES];
    let ciphertext_cca = I::indcpa_kem_enc(&m, r, pk_cca.pk_cpa());
    r.copy_from_slice(Sha3_256::digest(ciphertext_cca.as_ref()).as_slice());
    let mut sessionkey_cca = [0; KEYBYTES];
    (&mut sessionkey_cca).copy_from_slice(Sha3_256::digest(kr).as_slice());
    (SharedSecret { sessionkey_cca }, ciphertext_cca)
}

/// This function implements Saber.KEM.Decaps, as described in Algorithm 28
pub fn decapsulate<I: SaberImpl>(ct: &I::Ciphertext, sk: &I::SecretKey) -> SharedSecret {
    let (z, hash_pk, pk_cca, sk_cpa) = sk.unpack();
    let pk_cpa = pk_cca.pk_cpa();

    let m = I::indcpa_kem_dec(&sk_cpa, &ct);
    let mut hasher = Sha3_512::default();
    hasher.input(hash_pk);
    hasher.input(m);
    let mut kr_digest = hasher.result();
    let kr = kr_digest.as_mut_slice();
    let (r, k) = kr.split_at_mut(KEYBYTES);

    let ciphertext_cca_check = I::indcpa_kem_enc(&m, r, &pk_cpa);
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
    SharedSecret { sessionkey_cca }
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
