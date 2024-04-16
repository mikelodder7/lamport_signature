/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::utils::separate_one_and_zero_values;
use crate::{LamportDigest, LamportError, LamportResult, MultiVec, Signature};
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

/// A one-time signing private key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SigningKey<T: LamportDigest> {
    pub(crate) zero_values: MultiVec<u8, 2>,
    pub(crate) one_values: MultiVec<u8, 2>,
    pub(crate) used: bool,
    pub(crate) algorithm: PhantomData<T>,
}

serde_impl!(SigningKey);
vec_impl!(SigningKey);

impl<T: LamportDigest> Zeroize for SigningKey<T> {
    fn zeroize(&mut self) {
        self.zero_values.zeroize();
        self.one_values.zeroize();
    }
}

impl<T: LamportDigest> SigningKey<T> {
    /// Has this key been used.
    pub fn used(&self) -> bool {
        self.used
    }

    /// Constructs a [`SigningKey`] with Digest algorithm type and the specified RNG.
    pub fn random(mut rng: impl RngCore + CryptoRng) -> SigningKey<T> {
        SigningKey {
            zero_values: T::random(&mut rng),
            one_values: T::random(&mut rng),
            used: false,
            algorithm: PhantomData,
        }
    }

    /// Signs the data.
    ///
    /// # Example
    ///
    /// ```
    /// use sha2::Sha256;
    /// use rand::SeedableRng;
    /// use rand_chacha::ChaCha12Rng;
    /// use lamport_signature_plus::{LamportFixedDigest, SigningKey};
    ///
    /// const SEED: [u8; 32] = [0; 32];
    /// let mut rng = ChaCha12Rng::from_seed(SEED);
    /// let mut private_key = SigningKey::<LamportFixedDigest<Sha256>>::new(&mut rng);
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// assert!(private_key.sign(MESSAGE).is_ok());
    /// ```
    pub fn sign<B: AsRef<[u8]>>(&mut self, data: B) -> LamportResult<Signature<T>> {
        if self.used {
            return Err(LamportError::PrivateKeyReuseError);
        }
        let data = data.as_ref();

        let data_hash = T::digest(data);

        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;
        let mut data = MultiVec::fill([bits, bytes], 0);
        // Ensure runtime is independent of secret keys
        // Ensure code access patterns are independent of secret keys
        // Ensure data access patterns are independent of secret keys
        {
            let mut signature_iter = data.iter_mut();
            let mut zero_iter = self.zero_values.iter();
            let mut one_iter = self.one_values.iter();
            for byte in data_hash.iter() {
                for j in 0..8 {
                    let b = (*byte >> j) & 1;
                    let choice = Choice::from(b);
                    for _ in 0..bytes {
                        *signature_iter.next().expect("more values") = u8::conditional_select(
                            zero_iter.next().expect("more values"),
                            one_iter.next().expect("more values"),
                            choice,
                        );
                    }
                }
            }
        }

        self.used = true;
        Ok(Signature {
            data,
            algorithm: PhantomData,
        })
    }

    /// Converts the [`SigningKey`] to canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;
        let mut bytes = vec![0u8; 1 + bytes * bits * 2];
        bytes[0] = self.used as u8;
        let iter = bytes[1..].iter_mut();
        for (i, z) in iter.zip(self.zero_values.iter().chain(self.one_values.iter())) {
            *i = *z;
        }
        bytes
    }

    /// Constructs a [`SigningKey`] from canonical bytes.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;

        if input.len() != bits * bytes * 2 + 1 {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let used = input[0] == 1;
        let (zero_values, one_values) = separate_one_and_zero_values(&input[1..], bytes);
        Ok(Self {
            used,
            zero_values,
            one_values,
            algorithm: PhantomData,
        })
    }
}
