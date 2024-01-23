use std::ops::{Add, Sub};

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT as G},
    ristretto::RistrettoPoint,
    scalar::Scalar,
    traits::MultiscalarMul,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

lazy_static::lazy_static! {
    // base point for encoding the commitments opening
    pub static ref H: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<sha3::Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
}

/// Wrapper type around a decrypted point. Used as return value of `decrypt` to allow fast decoding of integers.
pub struct ECDLPInstance(RistrettoPoint);

impl ECDLPInstance {
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ElGamalPubkey(RistrettoPoint);

impl ElGamalPubkey {
    pub fn from_point(p: RistrettoPoint) -> Self {
        Self(p)
    }

    pub fn new(secret: &ElGamalSecretKey) -> Self {
        let s = &secret.0;
        assert!(s != &Scalar::zero());

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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, Zeroize)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ElGamalKeypair {
    pk: ElGamalPubkey,
    sk: ElGamalSecretKey,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
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
}

impl ElGamalKeypair {
    pub fn pubkey(&self) -> &ElGamalPubkey {
        &self.pk
    }

    pub fn secret(&self) -> &ElGamalSecretKey {
        &self.sk
    }
}

impl ElGamalKeypair {
    pub fn keygen() -> Self {
        // secret scalar should be non-zero except with negligible probability
        let mut s = Scalar::random(&mut OsRng);
        let keypair = Self::keygen_with_secret(&s);

        s.zeroize();
        keypair
    }

    pub fn keygen_with_secret(s: &Scalar) -> Self {
        let sk = ElGamalSecretKey(*s);
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
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

impl Add for &PedersenCommitment {
    type Output = PedersenCommitment;
    fn add(self, o: Self) -> Self::Output {
        PedersenCommitment(self.as_point() + o.as_point())
    }
}

impl Add for &ElGamalCiphertext {
    type Output = ElGamalCiphertext;
    fn add(self, o: Self) -> Self::Output {
        ElGamalCiphertext {
            commitment: &self.commitment + &o.commitment,
            handle: &self.handle + &o.handle,
        }
    }
}

impl Sub for &DecryptHandle {
    type Output = DecryptHandle;
    fn sub(self, o: Self) -> Self::Output {
        DecryptHandle(self.as_point() - o.as_point())
    }
}

impl Sub for &PedersenCommitment {
    type Output = PedersenCommitment;
    fn sub(self, o: Self) -> Self::Output {
        PedersenCommitment(self.as_point() - o.as_point())
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
