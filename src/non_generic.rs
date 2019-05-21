macro_rules! __generate_non_generic_impl {
    ($struct:ident) => {
        /// A saber public key
        #[repr(C)]
        #[derive(Clone)]
        pub struct PublicKey {
            pk_cpa: INDCPAPublicKey,
        }

        impl generic::PublicKey<$struct> for PublicKey {
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
                <PublicKey as generic::PublicKey<$struct>>::to_bytes(&self)
            }

            pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, crate::Error> {
                generic::PublicKey::from_bytes(bytes)
            }
        }

        impl From<&PublicKeyBytes> for PublicKey {
            fn from(newtype: &PublicKeyBytes) -> PublicKey {
                <PublicKey as generic::PublicKey<$struct>>::from_newtype(newtype)
            }
        }

        impl<'a> From<&'a SecretKey> for &'a PublicKey {
            fn from(sk: &SecretKey) -> &PublicKey {
                sk.public_key()
            }
        }

        __byte_array_newtype!(doc="
        A public key formatted as a byte string.

        This data structure is used for conversions between public keys and byte strings.
        ", pub PublicKeyBytes, PUBLIC_KEY_BYTES, [u8; PUBLIC_KEY_BYTES]);

        impl std::fmt::Debug for PublicKeyBytes {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "PublicKeyBytes([")?;
                for b in self.0.iter() {
                    write!(f, "0x{:02x}, ", b)?;
                }
                write!(f, "])")
            }
        }

        /// A saber secret key
        ///
        /// Secret keys also contain their respective public keys. These can be obtained using
        /// [`SecretKey::public_key()`].
        ///
        /// [`SecretKey::public_key()`]: struct.SecretKey.html#method.public_key
        #[repr(C)]
        #[derive(Clone)]
        pub struct SecretKey {
            z: [u8; KEYBYTES],
            hash_pk: [u8; HASHBYTES],
            pk_cca: PublicKey,
            sk_cpa: INDCPASecretKey,
        }

        impl generic::SecretKey<$struct> for SecretKey {
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
                <SecretKey as generic::SecretKey<$struct>>::from_newtype(newtype)
            }
        }

        impl SecretKey {
            /// Retrieve a reference to the public key that is contained in this secret key.
            pub fn public_key(&self) -> &PublicKey {
                &self.pk_cca
            }

            /// Serialize this secret key into bytes format.
            pub fn to_bytes(&self) -> SecretKeyBytes {
                <SecretKey as generic::SecretKey<$struct>>::to_bytes(self)
            }

            /// Parse the secret key in `bytes`.
            ///
            /// # Returns
            ///   - [`saber::Error::BadLength`], if `bytes` was of incorrect length.
            ///
            /// [`saber::Error::BadLength`]: ../enum.Error.html
            pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, crate::Error> {
                <SecretKey as generic::SecretKey<$struct>>::from_bytes(bytes)
            }
        }

        __byte_array_newtype!(doc="
        A secret key formatted as a byte string.

        This data structure is used for conversions between secret keys and byte strings.
        ", pub SecretKeyBytes, SECRET_KEY_BYTES, [u8; SECRET_KEY_BYTES]);

        #[repr(C)]
        #[derive(Clone)]
        struct INDCPAPublicKey {
            vec: Vector,
            seed: [u8; SEEDBYTES],
        }

        impl generic::INDCPAPublicKey<$struct> for INDCPAPublicKey {
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

        #[repr(C)]
        #[derive(Clone)]
        struct INDCPASecretKey {
            vec: Vector,
        }

        impl generic::INDCPASecretKey<$struct> for INDCPASecretKey {
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

        #[derive(Clone, Copy)]
        #[repr(C)]
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

        impl generic::Matrix<$struct, Vector> for Matrix {
            fn vecs(&self) -> &[Vector] {
                &self.vecs
            }

            fn vecs_mut(&mut self) -> &mut [Vector] {
                &mut self.vecs[..]
            }
        }

        /// Vector is equivalent to the reference implementation's `polyvec` type.
        #[derive(Clone, Copy, Default)]
        #[repr(C)]
        struct Vector {
            polys: [Poly; K],
        }

        impl generic::Vector<$struct> for Vector {
            fn polys(&self) -> &[Poly] {
                &self.polys
            }

            fn polys_mut(&mut self) -> &mut [Poly] {
                &mut self.polys
            }
        }

        __byte_array_newtype!(doc="
        A ciphertext formatted as a byte string.

        This data structure is used for conversions between ciphertexts and byte strings.
        ", pub Ciphertext, BYTES_CCA_DEC, [u8; BYTES_CCA_DEC]);

        /// Generate a saber keypair.
        ///
        /// # Example
        ///
        /// ```
        /// let secret_key = saber::saber::keygen();
        /// ```
        pub fn keygen() -> SecretKey {
            generic::keygen::<$struct>()
        }

        /// Encapsulate a secret destined for `pk_cca`.
        ///
        /// Takes a reference to Bob's [`PublicKey`] and returns a ([`SharedSecret`],
        /// [`Ciphertext`]) tuple.
        ///
        /// # Example
        ///
        /// ```
        /// use saber::saber::{PublicKey, encapsulate};
        ///
        /// # let pk_buf = [42u8; 992];
        /// // Assume `pk_buf` holds the bytes to a public key
        /// let public_key = saber::saber::PublicKey::from_bytes(&pk_buf).unwrap();
        /// let (shared_secret, ciphertext) = encapsulate(&public_key);
        /// ```
        ///
        /// [`PublicKey`]: struct.PublicKey.html
        /// [`SharedSecret`]: struct.SharedSecret.html
        /// [`Ciphertext`]: struct.Ciphertext.html
        pub fn encapsulate(pk_cca: &PublicKey) -> (SharedSecret, Ciphertext) {
            generic::encapsulate::<$struct>(&pk_cca)
        }

        /// Decapsulate a received ciphertext
        ///
        /// This function uses a `[SecretKey]` reference and decapsulate, sk: &SecretKey) the `[Ciphertext]`
        /// referenced by `ct`. A `[SharedSecret]` will be returned.
        /// In Saber, decryption failures are dealt with, so this function will always succeed.
        ///
        /// # Example
        ///
        /// ```
        /// use saber::saber::decapsulate;
        ///
        /// # let secret_key = saber::saber::keygen();
        /// # let (_, ciphertext) = saber::saber::encapsulate(secret_key.public_key());
        /// // Assume `secret_key` holds your secret key and you just received `ciphertext`
        /// decapsulate(&ciphertext, &secret_key);
        /// ```
        pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret {
            generic::decapsulate::<$struct>(ct, sk)
        }

    };
}

macro_rules! __generate_non_generic_tests {
    ($struct:ident) => {
        #[cfg(test)]
        mod __non_generic_tests {
            use super::*;

            #[test]
            fn test_kem() {
                let sk: SecretKey = keygen();
                let pk: &PublicKey = &sk.pk_cca;
                let (s1_newtype, ct): (SharedSecret, Ciphertext) = encapsulate(pk);
                let s1 = s1_newtype.as_bytes();
                let s2 = decapsulate(&ct, &sk).into_bytes();
                for (b1, b2) in s1.iter().zip(s2.iter()) {
                    assert_eq!(b1, b2);
                }
            }

            #[test]
            fn test_indcpa() {
                use rand_os::rand_core::RngCore;

                let (pk, sk) = generic::indcpa_kem_keypair::<$struct>();
                for _ in 0..100 {
                    let mut rng = rand_os::OsRng::new().unwrap();
                    let mut noiseseed = [0; NOISE_SEEDBYTES];
                    rng.fill_bytes(&mut noiseseed);
                    let mut message_received = [0; KEYBYTES];
                    rng.fill_bytes(&mut message_received);
                    let ciphertext =
                        generic::indcpa_kem_enc::<$struct>(&message_received, &noiseseed, &pk);
                    let message_dec = generic::indcpa_kem_dec::<$struct>(&sk, &ciphertext);
                    assert_eq!(&message_dec[..], &message_received[..]);
                }
            }

            #[test]
            #[ignore]
            fn test_kem_encapsulate_uninitialized() {
                let sk: SecretKey = unsafe { core::mem::uninitialized() };
                let pk = &sk.pk_cca;
                encapsulate(pk);
            }

            #[test]
            #[ignore]
            fn test_kem_decapsulate_uninitialized() {
                let sk: SecretKey = unsafe { core::mem::uninitialized() };
                let ct: Ciphertext = unsafe { core::mem::uninitialized() };
                decapsulate(&ct, &sk).into_bytes();
            }

            #[test]
            #[ignore]
            fn test_indcpa_keygen_uninitialized() {
                use crate::generic::{
                    indcpa_kem_keypair_deterministic, INDCPAPublicKey as _, INDCPASecretKey as _,
                };

                let seed: [u8; SEEDBYTES] = unsafe { core::mem::uninitialized() };
                let noise: [u8; COINBYTES] = unsafe { core::mem::uninitialized() };
                let (pk_cpa, sk_cpa) = indcpa_kem_keypair_deterministic::<$struct>(seed, noise);
                pk_cpa.to_bytes();
                sk_cpa.to_bytes();
            }

            #[test]
            #[ignore]
            fn test_indcpa_kem_enc_uninitialized() {
                use crate::generic::indcpa_kem_enc;

                let message_received: [u8; KEYBYTES] = unsafe { core::mem::uninitialized() };
                let noise: [u8; COINBYTES] = unsafe { core::mem::uninitialized() };

                let pk_cpa = unsafe { core::mem::uninitialized() };
                indcpa_kem_enc::<$struct>(&message_received, &noise, pk_cpa);
            }

            #[test]
            #[ignore]
            fn test_indcpa_kem_dec_uninitialized() {
                use crate::generic::indcpa_kem_dec;

                let ciphertext: Ciphertext = unsafe { core::mem::uninitialized() };
                let sk_cpa = unsafe { core::mem::uninitialized() };
                indcpa_kem_dec::<$struct>(&sk_cpa, &ciphertext);
            }

            #[test]
            fn polyveccompressedbytes_value() {
                assert_eq!(POLYVECCOMPRESSEDBYTES + SEEDBYTES, INDCPA_PUBLICKEYBYTES);
            }

            #[test]
            fn test_msg2pol_const_value() {
                assert_eq!(1 << (MSG2POL_CONST + 1), P);
            }
        }
    };
}
