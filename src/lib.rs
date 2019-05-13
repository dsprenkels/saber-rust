#![allow(clippy::suspicious_arithmetic_impl)]

extern crate rand;
extern crate sha3;

#[macro_use]
mod macros;

mod common;
mod params;
mod poly;
mod saber;
mod traits;

use common::*;

use rand::random;
use sha3::{Digest, Sha3_256, Sha3_512};

pub enum Error {
    BadLengthError {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
    #[doc(hidden)]
    __Nonexhaustive,
}

// impl PublicKey {
//     pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
//         self.pk_cpa.to_bytes()
//     }
//
//     pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
//         if bytes.len() != PUBLIC_KEY_BYTES {
//             let err = Error::BadLengthError {
//                 name: "bytes",
//                 actual: bytes.len(),
//                 expected: PUBLIC_KEY_BYTES,
//             };
//             return Err(err);
//         }
//         let pk_cpa = pke::PublicKey::from_bytes(bytes);
//         Ok(PublicKey { pk_cpa })
//     }
// }

// impl<'a> From<&'a SecretKey> for &'a PublicKey {
//     fn from(sk: &SecretKey) -> &PublicKey {
//         sk.public_key()
//     }
// }

// #[derive(Clone)]
// pub struct SecretKey {
//     z: [u8; KEYBYTES],
//     hash_pk: [u8; HASHBYTES],
//     pk_cca: PublicKey,
//     sk_cpa: pke::SecretKey,
// }
//
// #[derive(Clone)]
// pub struct Ciphertext {
//     ciphertext_cca: [u8; CIPHERTEXT_BYTES],
// }
//
// impl Ciphertext {
//     pub fn to_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
//         unimplemented!()
//     }
//
//     pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
//         &self.ciphertext_cca
//     }
//
//     pub fn from_bytes(bytes: &[u8]) -> Result<Ciphertext, Error> {
//         unimplemented!()
//     }
// }
//
// impl AsRef<[u8]> for Ciphertext {
//     fn as_ref(&self) -> &[u8] {
//         self.as_bytes()
//     }
// }

// /// This function implements Saber.KEM.KeyGen, as described in Algorithm 26
// pub fn keygen<'a>() -> SecretKey {
//     let (pk_cpa, sk_cpa) = pke::indcpa_kem_keypair();
//     let mut hash_pk = [0; HASHBYTES];
//     hash_pk.copy_from_slice(Sha3_256::digest(&pk_cpa.to_bytes()).as_slice());
//     let z: [u8; KEYBYTES] = random();
//     let sk_cca = SecretKey {
//         z,
//         hash_pk,
//         pk_cca: PublicKey { pk_cpa },
//         sk_cpa,
//     };
//     sk_cca
// }
//
// /// This function implements Saber.KEM.Encaps, as described in Algorithm 27
// pub fn encapsulate(pk_cca: &PublicKey) -> (SharedSecret, Ciphertext) {
//     let m: [u8; KEYBYTES] = random();
//     let hash_pk = Sha3_256::digest(&pk_cca.to_bytes());
//     let mut hasher = Sha3_512::default();
//     hasher.input(hash_pk);
//     hasher.input(m);
//     let mut kr_digest = hasher.result();
//     let kr = kr_digest.as_mut_slice();
//     let r = &mut kr[0..KEYBYTES];
//     let ciphertext_cca = pke::indcpa_kem_enc(&m, r, &pk_cca.pk_cpa);
//     r.copy_from_slice(Sha3_256::digest(&ciphertext_cca).as_slice());
//     let mut sessionkey_cca = [0; KEYBYTES];
//     (&mut sessionkey_cca).copy_from_slice(Sha3_256::digest(kr).as_slice());
//     (
//         SharedSecret { sessionkey_cca },
//         Ciphertext { ciphertext_cca },
//     )
// }
//
// /// This function implements Saber.KEM.Decaps, as described in Algorithm 28
// pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
//     let SecretKey {
//         z,
//         hash_pk,
//         pk_cca: PublicKey { pk_cpa },
//         sk_cpa,
//     } = sk;
//     let m = pke::indcpa_kem_dec(&sk_cpa, &ct.ciphertext_cca);
//     let mut hasher = Sha3_512::default();
//     hasher.input(hash_pk);
//     hasher.input(m);
//     let mut kr_digest = hasher.result();
//     let kr = kr_digest.as_mut_slice();
//     let (r, k) = kr.split_at_mut(KEYBYTES);
//
//     let ciphertext_cca_check = pke::indcpa_kem_enc(&m, r, &pk_cpa);
//     let fail = !compare_ct(&ciphertext_cca_check, &ct.ciphertext_cca);
//     r.copy_from_slice(Sha3_256::digest(&ciphertext_cca_check).as_slice());
//
//     let mut hasher = Sha3_256::default();
//     for (rb, zb) in r.iter().zip(z.iter()) {
//         let mask = (fail as u8).wrapping_neg();
//         let b = (rb & !mask) | (zb & mask);
//         hasher.input([b]);
//     }
//     hasher.input(k);
//
//     let mut sessionkey_cca = [0; KEYBYTES];
//     sessionkey_cca.copy_from_slice(hasher.result().as_slice());
//     SharedSecret { sessionkey_cca }
// }
//
// /// This function implements Verify, with some tweaks.
// ///
// /// The design document ambiguously specifies which of `true` and `false` mean that the strings
// /// were actually equal. The reference implementation return 0, when the strings are equal.
// /// However, this is Rust, and we follow conventions. So this function returns true if the strings
// /// are equal, otherwise false. I.e.
// fn compare_ct(buf1: &[u8], buf2: &[u8]) -> bool {
//     if buf1.len() != buf2.len() {
//         return false;
//     }
//     let mut acc = true;
//     for (b1, b2) in buf1.iter().zip(buf2.iter()) {
//         acc |= b1 == b2;
//     }
//     acc
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_kem() {
//         let sk = keygen();
//         let pk = sk.public_key();
//         let (s1, ct) = encapsulate(pk);
//         let s2 = decapsulate(&ct, &sk);
//         assert_eq!(&s1.sessionkey_cca, &s2.sessionkey_cca);
//     }
// }
