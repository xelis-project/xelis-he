//! Twisted ElGamal implementation.

use std::ops::{Add, AddAssign, Sub, SubAssign};

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT as G},
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::{Identity, MultiscalarMul},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;
use serde::de::Error as SerdeError;

lazy_static::lazy_static! {
    // base point for encoding the commitments opening
    pub static ref H: RistrettoPoint = {
        let mut hasher = sha3::Sha3_512::default();
        hasher.update(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
        let hash = hasher.finalize();
        RistrettoPoint::from_uniform_bytes(hash.as_ref())
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    s: Scalar,
    e: Scalar,
}

impl Signature {
    pub fn new(s: Scalar, e: Scalar) -> Self {
        Self { s, e }
    }

    // Verify the signature using the Public Key and the hash of the message
    pub fn verify(&self, message: &[u8], key: &ElGamalPubkey) -> bool {
        let r = *H * &self.s + key.as_point() * -self.e;
        let calculated = hash_and_point_to_scalar(&key.compress(), message, &r);
        self.e == calculated
    }
}

// Create a Scalar from Public Key, Hash of the message, and selected point
pub fn hash_and_point_to_scalar(key: &CompressedPubkey, message: &[u8], point: &RistrettoPoint) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(&key.0);
    hasher.update(message);
    hasher.update(point.compress().as_bytes());

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.try_into().unwrap())
}

/// Wrapper type around a decrypted point. Used as return value of `decrypt` to allow fast decoding of integers.
pub struct ECDLPInstance(RistrettoPoint);

pub use curve25519_dalek::ecdlp;

use crate::{CompressedCiphertext, CompressedPubkey};

impl ECDLPInstance {
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    pub fn decode<TS: ecdlp::PrecomputedECDLPTables, R: ecdlp::ProgressReportFunction>(
        &self,
        precomputed_tables: &TS,
        args: ecdlp::ECDLPArguments<R>,
    ) -> Option<i64> {
        ecdlp::decode(precomputed_tables, *self.as_point(), args)
    }

    pub fn par_decode<TS: ecdlp::PrecomputedECDLPTables + Sync, R: ecdlp::ProgressReportFunction + Sync>(
        &self,
        precomputed_tables: &TS,
        args: ecdlp::ECDLPArguments<R>,
    ) -> Option<i64> {
        ecdlp::par_decode(precomputed_tables, *self.as_point(), args)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElGamalPubkey(RistrettoPoint);

impl ElGamalPubkey {
    pub fn from_point(p: RistrettoPoint) -> Self {
        Self(p)
    }

    pub fn new(secret: &ElGamalSecretKey) -> Self {
        let s = &secret.0;
        assert!(s != &Scalar::ZERO);

        ElGamalPubkey(s.invert() * &(*H))
    }

    pub fn encrypt<T: Into<Scalar>>(&self, amount: T) -> ElGamalCiphertext {
        let (commitment, opening) = PedersenCommitment::new(amount);
        let handle = self.decrypt_handle(&opening);

        ElGamalCiphertext { commitment, handle }
    }

    pub fn encrypt_with_opening<T: Into<Scalar>>(
        &self,
        amount: T,
        opening: &PedersenOpening,
    ) -> ElGamalCiphertext {
        let commitment = PedersenCommitment::new_with_opening(amount, opening);
        let handle = self.decrypt_handle(opening);

        ElGamalCiphertext { commitment, handle }
    }

    pub fn decrypt_handle(&self, opening: &PedersenOpening) -> DecryptHandle {
        DecryptHandle::new(&self, opening)
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct ElGamalSecretKey(Scalar);

impl ElGamalSecretKey {
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> ECDLPInstance {
        let point = ciphertext.commitment.as_point() - &(&self.0 * &ciphertext.handle.0);

        ECDLPInstance(point)
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalKeypair {
    pk: ElGamalPubkey,
    sk: ElGamalSecretKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    commitment: PedersenCommitment,
    handle: DecryptHandle,
}

impl ElGamalCiphertext {
    pub fn commitment(&self) -> &PedersenCommitment {
        &self.commitment
    }
    pub fn handle(&self) -> &DecryptHandle {
        &self.handle
    }

    pub fn new(commitment: PedersenCommitment, handle: DecryptHandle) -> Self {
        Self { commitment, handle }
    }

    /// Create a ciphertext with a zero value
    pub fn zero() -> Self {
        Self {
            commitment: PedersenCommitment::from_point(RistrettoPoint::identity()),
            handle: DecryptHandle::from_point(RistrettoPoint::identity()),
        }
    }
}

impl ElGamalKeypair {
    pub fn pubkey(&self) -> &ElGamalPubkey {
        &self.pk
    }

    pub fn secret(&self) -> &ElGamalSecretKey {
        &self.sk
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let k = Scalar::random(&mut OsRng);
        let r = k * *H;
        let e = hash_and_point_to_scalar(&self.pk.compress(), message, &r);
        let s = self.sk.as_scalar().invert() * e + k;
        Signature::new(s, e)
    }
}

impl ElGamalKeypair {
    pub fn keygen() -> Self {
        // secret scalar should be non-zero except with negligible probability
        let s = Scalar::random(&mut OsRng);
        let keypair = Self::keygen_with_secret(s);

        keypair
    }

    pub fn keygen_with_secret(s: Scalar) -> Self {
        let sk = ElGamalSecretKey(s);
        let pk = ElGamalPubkey::new(&sk);

        Self { pk, sk }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DecryptHandle(RistrettoPoint);

impl DecryptHandle {
    pub fn from_point(p: RistrettoPoint) -> Self {
        Self(p)
    }

    pub fn new(public: &ElGamalPubkey, opening: &PedersenOpening) -> Self {
        Self(&public.0 * opening.as_scalar())
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenOpening(Scalar);
impl PedersenOpening {
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self(scalar)
    }
    pub fn generate_new() -> Self {
        PedersenOpening(Scalar::random(&mut OsRng))
    }

    pub fn as_scalar(&self) -> Scalar {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCommitment(RistrettoPoint);
impl PedersenCommitment {
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self(point)
    }

    pub fn new<T: Into<Scalar>>(amount: T) -> (PedersenCommitment, PedersenOpening) {
        let opening = PedersenOpening::generate_new();
        let commitment = Self::new_with_opening(amount, &opening);

        (commitment, opening)
    }

    pub fn new_with_opening<T: Into<Scalar>>(amount: T, opening: &PedersenOpening) -> Self {
        let x: Scalar = amount.into();
        let r = opening.as_scalar();

        Self(RistrettoPoint::multiscalar_mul(&[x, r], &[G, *H]))
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }
}

// Homomorphic properties

impl Add for &DecryptHandle {
    type Output = DecryptHandle;
    fn add(self, o: Self) -> Self::Output {
        DecryptHandle(self.as_point() + o.as_point())
    }
}

impl Sub for &DecryptHandle {
    type Output = DecryptHandle;
    fn sub(self, o: Self) -> Self::Output {
        DecryptHandle(self.as_point() - o.as_point())
    }
}

make_add_variants!(DecryptHandle, DecryptHandle, Output = DecryptHandle);
make_sub_variants!(DecryptHandle, DecryptHandle, Output = DecryptHandle);

impl Add for &PedersenCommitment {
    type Output = PedersenCommitment;
    fn add(self, o: Self) -> Self::Output {
        PedersenCommitment(self.as_point() + o.as_point())
    }
}

impl Sub for &PedersenCommitment {
    type Output = PedersenCommitment;
    fn sub(self, o: Self) -> Self::Output {
        PedersenCommitment(self.as_point() - o.as_point())
    }
}

make_add_variants!(
    PedersenCommitment,
    PedersenCommitment,
    Output = PedersenCommitment
);
make_sub_variants!(
    PedersenCommitment,
    PedersenCommitment,
    Output = PedersenCommitment
);

impl Add for &ElGamalCiphertext {
    type Output = ElGamalCiphertext;
    fn add(self, o: Self) -> Self::Output {
        ElGamalCiphertext {
            commitment: &self.commitment + &o.commitment,
            handle: &self.handle + &o.handle,
        }
    }
}

impl Sub for &ElGamalCiphertext {
    type Output = ElGamalCiphertext;
    fn sub(self, o: Self) -> Self::Output {
        ElGamalCiphertext {
            commitment: &self.commitment - &o.commitment,
            handle: &self.handle - &o.handle,
        }
    }
}

make_add_variants!(
    ElGamalCiphertext,
    ElGamalCiphertext,
    Output = ElGamalCiphertext
);
make_sub_variants!(
    ElGamalCiphertext,
    ElGamalCiphertext,
    Output = ElGamalCiphertext
);

// ElGamalCiphertext + Scalar is equivalent to committing the scalar to a 0 opening (non-hiding)
// and performing the usual addition using that

impl Add<&Scalar> for &ElGamalCiphertext {
    type Output = ElGamalCiphertext;
    fn add(self, o: &Scalar) -> Self::Output {
        ElGamalCiphertext {
            commitment: PedersenCommitment::from_point(self.commitment.as_point() + &(&G * o)),
            handle: self.handle.clone(),
        }
    }
}

impl Sub<&Scalar> for &ElGamalCiphertext {
    type Output = ElGamalCiphertext;
    fn sub(self, o: &Scalar) -> Self::Output {
        ElGamalCiphertext {
            commitment: PedersenCommitment::from_point(self.commitment.as_point() - &(&G * o)),
            handle: self.handle.clone(),
        }
    }
}

make_add_variants!(ElGamalCiphertext, Scalar, Output = ElGamalCiphertext);
make_sub_variants!(ElGamalCiphertext, Scalar, Output = ElGamalCiphertext);

impl Serialize for ElGamalCiphertext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.compress().serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for ElGamalCiphertext {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let compressed = CompressedCiphertext::deserialize(deserializer)?;
        Ok(compressed.decompress().map_err(SerdeError::custom)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homomorphic_ct_scalar() {
        let keypair = ElGamalKeypair::keygen();

        let ct = keypair.pubkey().encrypt(60u64);

        assert_eq!(
            *keypair
                .secret()
                .decrypt(&(&ct + &Scalar::from(15u64)))
                .as_point(),
            &Scalar::from(75u64) * &G
        );
        assert_eq!(
            *keypair
                .secret()
                .decrypt(&(&ct - &Scalar::from(15u64)))
                .as_point(),
            &Scalar::from(45u64) * &G
        );
    }

    #[test]
    fn test_identity() {
        let keypair = ElGamalKeypair::keygen();

        let ct = keypair.pubkey().encrypt(0u64);

        assert_eq!(
            *keypair.secret().decrypt(&ct).as_point(),
            RistrettoPoint::identity()
        );
    }

    #[test]
    fn test_universal_identity() {
        let keypair = ElGamalKeypair::keygen();
        let ct = ElGamalCiphertext::zero();

        let point = *keypair.secret().decrypt(&ct).as_point();
        assert_eq!(
            point,
            RistrettoPoint::identity()
        );

        assert_eq!(
            point,
            Scalar::from(0u64) * G
        );
    }

    #[test]
    fn test_dud_commitment() {
        assert_eq!(
            PedersenCommitment::new_with_opening(
                Scalar::ZERO,
                &PedersenOpening::from_scalar(Scalar::ZERO)
            ),
            PedersenCommitment::from_point(RistrettoPoint::identity())
        );
    }

    #[test]
    fn test_signature() {
        let keypair = ElGamalKeypair::keygen();
        let message = b"Hello, world!";
        let signature = keypair.sign(message);

        assert!(signature.verify(message, keypair.pubkey()));
        assert!(!signature.verify(b"hello world", keypair.pubkey()));

        let keypair2 = ElGamalKeypair::keygen();
        assert!(!signature.verify(message, keypair2.pubkey()));
    }
}
