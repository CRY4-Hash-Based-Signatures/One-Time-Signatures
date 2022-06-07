use rand::RngCore;
use rand::prelude::ThreadRng;
use sha2::Digest;
use std::marker::PhantomData;
use bitvec::prelude::*;
use itertools::enumerate;
use crate::{OneTimePublicKey, OneTimeSecretKey, OneTimeSignature};

fn random_byte_vector(size: usize, rng: &mut ThreadRng) -> Vec<u8> {
    let mut vec = vec![0; size];
    rng.fill_bytes(&mut vec);
    vec
}

#[derive(Clone)]
pub struct LamportSignature {
    sig: Vec<Vec<u8>>
}

impl OneTimeSignature for LamportSignature {}

impl<'a> LamportSignature {
    pub fn len(&self) -> usize {
        self.sig.len()
    }

    pub fn elem_size(&self) -> usize{
        self.sig[0].len()
    }

    pub fn size(&self) -> usize {
        self.len() * self.elem_size()
    }

    pub fn get_elem(&self, i: usize) -> &[u8] {
        &self.sig[i]
    }
}

#[allow(non_snake_case)]
pub struct LamportSecretKey<D: Digest> {
    SK0: Vec<Vec<u8>>,
    SK1: Vec<Vec<u8>>,
    used: bool,
    p: PhantomData<D>
}

#[allow(non_snake_case)]
impl<D: Digest> LamportSecretKey<D> {
    pub fn new() -> LamportSecretKey<D> {
        let value_size_bytes: usize = <D as Digest>::output_size();
        let values: usize = value_size_bytes * 8;

        let mut rng = rand::thread_rng();
        let mut SK0 = Vec::with_capacity(values);
        let mut SK1 = Vec::with_capacity(values);

        for _ in 0..values {
            SK0.push(random_byte_vector(value_size_bytes, &mut rng));
            SK1.push(random_byte_vector(value_size_bytes, &mut rng));
        }
        LamportSecretKey { SK0, SK1, used: false, p: PhantomData }
    }

    pub fn sign(&mut self, m: &[u8]) -> Result<LamportSignature, String> {
        if self.used { return Err(String::from("This Lamport key has already been used to sign once")) }
        self.used = true;

        let size = self.len();

        // Assert that m is of size
        if m.len() * 8 != size {
            return Err(format!("Message must be {} bits. Use 'sign_arbitrary' for arbitrary message length", size))
        }

        //let barr: BitVec = m.into();
        let bv = BitVec::<_, Msb0>::from_slice(m);

        let sk0 = self.SK0.clone();
        let sk1 = self.SK1.clone();
        let sig = bv.into_iter().zip(sk0.into_iter().zip(sk1)).map(|(bit, (sk0, sk1))| if bit { sk1 } else { sk0 }).collect();

        Ok(LamportSignature { sig })
    }

    pub fn sign_arbitrary(&mut self, m: &[u8]) -> Result<LamportSignature, String> {
        self.sign(&D::digest(m))
    }

    pub fn len(&self) -> usize {
        self.SK0.len()
    }

    pub fn elem_size(&self) -> usize {
        <D as Digest>::output_size()
    }

    pub fn size(&self) -> usize {
        self.len() * self.elem_size()
    }
}

impl<D: Digest> OneTimeSecretKey<D> for LamportSecretKey<D> {
    fn sign(&mut self, m: &[u8]) -> Result<Box<dyn OneTimeSignature>, String> {
        match LamportSecretKey::sign(self, m) {
            Ok(sig) => {
                Ok(Box::new(sig))
            }
            Err(string) => {
                Err(string)
            }
        }
    }

    fn sign_arbitrary(&mut self, m: &[u8]) -> Result<Box<dyn OneTimeSignature>, String> {
        match LamportSecretKey::sign_arbitrary(self, m) {
            Ok(sig) => {
                Ok(Box::new(sig))
            }
            Err(string) => {
                Err(string)
            }
        }
    }
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct LamportPublicKey<D: Digest> {
    PK0: Vec<Vec<u8>>,
    PK1: Vec<Vec<u8>>,
    p: PhantomData<D>,
}

#[allow(non_snake_case)]
impl<D: Digest> LamportPublicKey<D> {
    pub fn new(SK: &LamportSecretKey<D>) -> LamportPublicKey<D> {
        let size = SK.len();

        let mut PK0 = Vec::with_capacity(size);
        let mut PK1 = Vec::with_capacity(size);

        for i in 0..size {
            PK0.push(D::digest(&SK.SK0[i]).to_vec());
            PK1.push(D::digest(&SK.SK1[i]).to_vec());
       }
       LamportPublicKey { PK0, PK1, p: PhantomData }
    }

    pub fn verify(&self, m: &[u8], sig: &LamportSignature) -> Result<(), String> {
        let len = self.len();
        if len != sig.len() {
            return Err(format!("Public key length ({} bytes) doesn't match signature length ({} bytes).", len, sig.len()))
        }

        if m.len() * 8 != len {
            return Err(format!("Message length ({} bytes) doesn't match public key length ({} bytes). Use 'verify_arbitrary' for arbitrary message length", m.len(), len))
        }
        
        let bv = BitVec::<_, Msb0>::from_slice(m);
        for (i, bit) in enumerate(bv) {
            let pk_elem = if bit { &self.PK1[i] } else { &self.PK0[i] };
            let h_sig = D::digest(&sig.get_elem(i)).to_vec();
            if h_sig != *pk_elem {
                return Err(String::from("Signature is wrong"))
            }
        }

        Ok(())
    }

    pub fn verify_arbitrary(&self, m: &[u8], sig: &LamportSignature) -> Result<(), String> {
        LamportPublicKey::verify(self, &D::digest(m), sig)
    }

    pub fn len(&self) -> usize {
        self.PK0.len()
    }

    pub fn elem_size(&self) -> usize {
        self.PK0[0].len()
    }

    pub fn size(&self) -> usize {
        self.len() * self.elem_size()
    }
}

impl<D: 'static + Digest + Clone> OneTimePublicKey<D> for LamportPublicKey<D> {
    fn verify(&self, m: &[u8], sig: &Box<dyn OneTimeSignature>) -> Result<(), String> {
        match sig.as_any().downcast_ref::<LamportSignature>() {
            Some(sig) => LamportPublicKey::verify(self, m, sig),
            None => Err(String::from("Wrong one time signature?"))
        }
    }

    fn verify_arbitrary(&self, m: &[u8], sig: &Box<dyn OneTimeSignature>) -> Result<(), String> {
        match sig.as_any().downcast_ref::<LamportSignature>() {
            Some(sig) => LamportPublicKey::verify_arbitrary(self, m, sig),
            None => Err(String::from("Wrong one time signature?"))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(2 * (self.PK0.len() * self.PK0[0].len()));
        self.PK0.iter().chain(self.PK1.iter())
            .for_each(|vec| ret.extend(vec));
        ret
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use sha2::{Sha256, Sha512};
    use super::*;
    const TEST_MESSAGE32: &[u8] = b"32 byte Lamport test message hih";
    const TEST_MESSAGE64: &[u8] = b"64 byte Lamport test message, used for wider hash functions outp";
    const TEST_MESSAGE_AB: &[u8] = b"An arbitrary length message used to test signing using digests";

    #[test]
    fn test_correct_signing_order() {
        // 0x97 == 1001_0111
        let m = &[0x97u8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        let mut sk = LamportSecretKey::<Sha256>::new();
        let sk_elems = [sk.SK1[0].clone(), sk.SK0[1].clone(), sk.SK0[2].clone(), sk.SK1[3].clone(), sk.SK0[4].clone(), sk.SK1[5].clone(), sk.SK1[6].clone(), sk.SK1[7].clone()];
        let sig = sk.sign(m).unwrap();

        for i in 0..8 {
            assert_eq!(sk_elems[i], sig.sig[i]);
        }
    }

    #[test]
    fn test_key_len() {
        let key = LamportSecretKey::<Sha256>::new();
        assert_eq!(key.len(), 256);
    }

    #[test]
    fn test_elem_size() {
        let key = LamportSecretKey::<Sha256>::new();
        assert_eq!(key.elem_size(), 32);
    }

    #[test]
    fn test_sk_value_is_32_bytes_sha256() {
        let key = LamportSecretKey::<Sha256>::new();
        assert_eq!(key.SK0[0].len(), 32);
        assert_eq!(key.SK1[0].len(), 32);
    }

    #[test]
    fn test_pk_is_hash_of_sk() {
        let SK = LamportSecretKey::<Sha256>::new();
        let PK = LamportPublicKey::<Sha256>::new(&SK);

        let sk0 = &SK.SK0[254];
        let pk0 = &PK.PK0[254];
        let sk1 = &SK.SK1[148];
        let pk1 = &PK.PK1[148];

        let hash_sk0 = Sha256::digest(sk0).to_vec();
        let hash_sk1 = Sha256::digest(sk1).to_vec();

        assert_eq!(*pk0, hash_sk0);
        assert_eq!(*pk1, hash_sk1);
    }

    #[test]
    fn test_pk_is_hash_of_sk_512() {
        let SK = LamportSecretKey::<Sha512>::new();
        let PK = LamportPublicKey::<Sha512>::new(&SK);

        let sk0 = &SK.SK0[254];
        let pk0 = &PK.PK0[254];
        let sk1 = &SK.SK1[148];
        let pk1 = &PK.PK1[148];

        let hash_sk0 = Sha512::digest(sk0).to_vec();
        let hash_sk1 = Sha512::digest(sk1).to_vec();

        assert_eq!(*pk0, hash_sk0);
        assert_eq!(*pk1, hash_sk1);
    }

    #[test]
    fn test_sign_verify() {
        let mut SK = LamportSecretKey::<Sha256>::new();
        let PK = LamportPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        PK.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_arbitrary() {
        let mut SK = LamportSecretKey::<Sha256>::new();
        let PK = LamportPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign_arbitrary(TEST_MESSAGE_AB).unwrap();
        PK.verify_arbitrary(TEST_MESSAGE_AB, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_wrong_sig() {
        let mut SK = LamportSecretKey::<Sha256>::new();
        let PK = LamportPublicKey::<Sha256>::new(&SK);

        let mut sig = SK.sign(TEST_MESSAGE32).unwrap();
        sig.sig[17][6] ^= 1;
        let res = PK.verify(TEST_MESSAGE32, &sig);

        assert!(res.is_err());
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let mut SK = LamportSecretKey::<Sha256>::new();
        let PK = LamportPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        let new_message = b"This is a different message, so ";
        let res = PK.verify(new_message, &sig);

        assert!(res.is_err());
    }

    #[test]
    fn test_sign_wrong_message_size() {
        let mut SK = LamportSecretKey::<Sha256>::new();

        let sig = SK.sign(TEST_MESSAGE64);

        assert!(sig.is_err());
    }

    #[test]
    fn test_sign_already_used() {
        let mut SK = LamportSecretKey::<Sha256>::new();
        let PK = LamportPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        PK.verify(TEST_MESSAGE32, &sig).unwrap();

        let sig = SK.sign(TEST_MESSAGE32);

        assert!(sig.is_err());
    }
}
