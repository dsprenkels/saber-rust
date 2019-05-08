pub const PUBLICKEYBYTES: usize = 992;
pub const SECRETKEYBYTES: usize = 2304;

use crate::params::*;
use crate::pke;

use rand::random;
use sha3::{Digest, Sha3_256, Sha3_512};

#[derive(Clone)]
pub struct PublicKey {
    pk_cpa: pke::PublicKey,
}

impl PublicKey {
    fn to_bytes(&self) -> [u8; PUBLICKEYBYTES] {
        self.pk_cpa.to_bytes()
    }
}

#[derive(Clone)]
pub struct SecretKey {
    z: [u8; KEYBYTES],
    hash_pk: [u8; HASHBYTES],
    pk_cpa: pke::PublicKey,
    sk_cpa: pke::SecretKey,
}

#[derive(Clone)]
pub struct SharedSecret {
    sessionkey_cca: [u8; KEYBYTES],
}

#[derive(Clone)]
pub struct Ciphertext {
    ciphertext_cca: [u8; pke::BYTES_CCA_DEC],
}

/// This function implements Saber.KEM.KeyGen, as described in Algorithm 26
pub fn keypair() -> (PublicKey, SecretKey) {
    let (pk_cpa, sk_cpa) = pke::indcpa_kem_keypair();
    let mut hash_pk = [0; HASHBYTES];
    hash_pk.copy_from_slice(Sha3_256::digest(&pk_cpa.to_bytes()).as_slice());
    let z: [u8; KEYBYTES] = random();
    let sk_cca = SecretKey {
        z,
        hash_pk,
        pk_cpa: pk_cpa.clone(),
        sk_cpa,
    };
    (PublicKey { pk_cpa }, sk_cca)
}

/// This function implements Saber.KEM.Encaps, as described in Algorithm 27
pub fn encapsulate(pk_cca: PublicKey) -> (SharedSecret, Ciphertext) {
    let m: [u8; KEYBYTES] = random();
    let hash_pk = Sha3_256::digest(&pk_cca.to_bytes());
    let mut hasher = Sha3_512::default();
    hasher.input(hash_pk);
    hasher.input(m);
    let mut kr_digest = hasher.result();
    let kr = kr_digest.as_mut_slice();
    let r = &mut kr[0..KEYBYTES];
    let ciphertext_cca = pke::indcpa_kem_enc(&m, r, &pk_cca.pk_cpa);
    r.copy_from_slice(Sha3_256::digest(&ciphertext_cca).as_slice());
    let mut sessionkey_cca = [0; KEYBYTES];
    (&mut sessionkey_cca).copy_from_slice(Sha3_256::digest(kr).as_slice());
    (
        SharedSecret { sessionkey_cca },
        Ciphertext { ciphertext_cca },
    )
}

/// This function implements Saber.KEM.Decaps, as described in Algorithm 28
pub fn decapsulate(ct: Ciphertext, sk: SecretKey) -> SharedSecret {
    let SecretKey {
        z,
        hash_pk,
        pk_cpa,
        sk_cpa,
    } = sk;
    let m = pke::indcpa_kem_dec(&sk_cpa, &ct.ciphertext_cca);
    let mut hasher = Sha3_512::default();
    hasher.input(hash_pk);
    hasher.input(m);
    let mut kr_digest = hasher.result();
    let kr = kr_digest.as_mut_slice();
    let (r, k) = kr.split_at_mut(KEYBYTES);

    let ciphertext_cca_check = pke::indcpa_kem_enc(&m, r, &pk_cpa);
    let fail = !compare_ct(&ciphertext_cca_check, &ct.ciphertext_cca);
    r.copy_from_slice(Sha3_256::digest(&ciphertext_cca_check).as_slice());

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem() {
        let (pk, sk) = keypair();
        let (s1, ct) = encapsulate(pk);
        let s2 = decapsulate(ct, sk);
        assert_eq!(&s1.sessionkey_cca, &s2.sessionkey_cca);
    }
}