use sha2::Digest;
use std::marker::PhantomData;
use rand::prelude::ThreadRng;
use rand::RngCore;

use crate::{OneTimePublicKey, OneTimeSecretKey, OneTimeSignature};

fn len1(w: usize, n: usize) -> usize {
    ((8 * n) as f64 / (w as f64).log2()).ceil() as usize
}

fn len2(w: usize, n: usize) -> usize {
    (((len1(w, n) * (w - 1)) as f64).log2() / (w as f64).log2()).floor() as usize + 1
}

fn len(w: usize, n: usize) -> usize {
    len1(w, n) + len2(w, n)
}

fn base_w(message: &[u8], w: usize, out_len: usize) -> Vec<u32> {
    let w = w as u32;
    let mut inv = 0;
    let mut out = 0;
    let mut total: u32 = 0;
    let mut bits = 0;
    let lg_w = match w {
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!("Cannot compute base-w with w: {} not in {{4,16,256}}", w)
    };

    let mut base_w_x = vec![0; out_len as usize];

    for _ in 0..out_len {
        if bits == 0 {
            total = message[inv] as u32;
            inv += 1;
            bits += 8;
        }
        bits -= lg_w;
        base_w_x[out] = (total >> bits) & (w - 1);
        out += 1;
    }

    base_w_x
}

fn get_checksum(m: &[u32], w: usize, len2: usize) -> Vec<u32> {
    let lg_w = match w {
        4 => 2,
        16 => 4,
        256 => 8,
        _ => panic!("Cannot compute base-w with w: {} not in {{4,16,256}}", w)
    };
    let mut checksum = m.iter().fold(0,|acc, &m_elem| acc + w - 1 - m_elem as usize);

    checksum <<= (8 - ((len2 * lg_w) % 8)) % 8;
    let cksum = checksum.to_be_bytes();

    base_w(&cksum, w, len2).to_vec()
}

fn random_byte_vector(size: usize, rng: &mut ThreadRng) -> Vec<u8> {
    let mut vec = vec![0; size];
    rng.fill_bytes(&mut vec);
    vec
}

fn iterate_hash<D: Digest>(to_hash: &[u8], times: usize) -> Vec<u8> {
    if times == 0 {
        return (*to_hash).to_vec()
    }

    let mut hash = D::digest(to_hash);
    for _ in 0..(times-1) {
        hash = D::digest(hash);
    }
    
    hash.to_vec()
}

pub struct WinternitzSignature {
    sig: Vec<Vec<u8>>,
}

impl WinternitzSignature {
    pub fn len(&self) -> usize {
        self.sig.len()
    }
}

impl OneTimeSignature for WinternitzSignature {}

pub struct WinternitzSecretKey<D: Digest> {
    w: usize,
    n: usize,
    sk: Vec<Vec<u8>>,
    used: bool,
    p: PhantomData<D>,
}

impl<D: Digest> WinternitzSecretKey<D> {
    pub fn new(w: usize) -> WinternitzSecretKey<D> {
        let n = <D as Digest>::output_size();
        let len = len(w, n);
        let mut sk = Vec::with_capacity(len);

        let mut rng = rand::thread_rng();
        for _ in 0..len {
            sk.push(random_byte_vector(<D as Digest>::output_size(), &mut rng));
        }

        WinternitzSecretKey { w, n, sk, used: false, p: PhantomData }
    }

    pub fn sign(&mut self, m: &[u8]) -> Result<WinternitzSignature, String> {
        if self.used { return Err(String::from("This Winternitz key has already been used to sign a message")) }
        self.used = true;

        let m_w = &base_w(m, self.w, len1(self.w, self.n));
        let len1 = len1(self.w, self.n);
        let len2 = len2(self.w, self.n);
        let len = len(self.w, self.n);

        if m.len() != self.n {
            return Err(format!("Message is {} bytes, but {} is required. Use sign_arbitrary for arbitrary length messages", m.len(), len1))
        }

        let mut sig = Vec::with_capacity(len);
        let checksum = get_checksum(m_w, self.w, len2);

        for i in 0..len {
            let times_to_hash = if i < len1 { m_w[i] as usize } else { checksum[i-len1] as usize };
            let sig_elem = iterate_hash::<D>(&self.sk[i], times_to_hash).to_vec();
            sig.push(sig_elem);
        }

        Ok(WinternitzSignature { sig })
    }

    pub fn sign_arbitrary(&mut self, m: &[u8]) -> Result<WinternitzSignature, String> {
        self.sign(&D::digest(m))
    }

    pub fn len(&self) -> usize {
        self.sk.len()
    }
}

impl<D: Digest> OneTimeSecretKey<D> for WinternitzSecretKey<D> {
    fn sign(&mut self, m: &[u8]) -> Result<Box<dyn OneTimeSignature>, String> {
        match WinternitzSecretKey::sign(self, m) {
            Ok(sig) => {
                Ok(Box::new(sig))
            }
            Err(string) => {
                Err(string)
            }
        }
    }

    fn sign_arbitrary(&mut self, m: &[u8]) -> Result<Box<dyn OneTimeSignature>, String> {
        match WinternitzSecretKey::sign_arbitrary(self, m) {
            Ok(sig) => {
                Ok(Box::new(sig))
            }
            Err(string) => {
                Err(string)
            }
        }
    }
}

#[derive(Clone)]
pub struct WinternitzPublicKey<D> {
    w: usize,
    n: usize,
    pk: Vec<Vec<u8>>,
    p: PhantomData<D>,
}

impl<D: Digest> WinternitzPublicKey<D> {
    pub fn new(wsk: &WinternitzSecretKey<D>) -> WinternitzPublicKey<D> {
        let len = len(wsk.w, wsk.n);
        
        let mut pk = Vec::with_capacity(len);

        for i in 0..len {
            let sk_elem = &wsk.sk[i];
            let pk_elem = iterate_hash::<D>(sk_elem, wsk.w - 1);
            pk.push(pk_elem);
        }

        WinternitzPublicKey { w: wsk.w, n: wsk.n, pk, p: PhantomData }
    }

    pub fn verify(&self, m: &[u8], sig: &WinternitzSignature) -> Result<(), String> {
        let len1 = len1(self.w, self.n);
        let len2 = len2(self.w, self.n);
        let len = len(self.w, self.n);

        let m_w = &base_w(m, self.w, len1);
        if self.pk.len() != sig.len() {
            return Err(format!("Public key length ({} bytes) doesn't match signature length ({} bytes).", self.pk.len(), sig.len()))
        }

        if m.len() != self.n {
            return Err(format!("Message (base-w) length ({} bytes) doesn't match digest size ({} bytes). Use 'verify_arbitrary' for arbitrary message length", m.len(), self.n))
        }

        let checksum = get_checksum(m_w, self.w, len2);

        let mut cand_pk = Vec::with_capacity(len);

        for i in 0..len {
            let init_times = if i < len1 { m_w[i] as usize } else { checksum[i-len1] as usize };
            let pk_elem = iterate_hash::<D>(&sig.sig[i], self.w - 1 - init_times);
            cand_pk.push(pk_elem);
        }

        for i in 0..len {
            if self.pk[i] != cand_pk[i] {
                return Err(String::from("Verification failed"))
            }
        }

        Ok(())
    }

    pub fn verify_arbitrary(&self, m: &[u8], sig: &WinternitzSignature) -> Result<(), String> {
        self.verify(&D::digest(m), sig)
    }

    pub fn len(&self) -> usize {
        self.pk.len()
    }
}

impl<D: Digest + Clone + 'static> OneTimePublicKey<D> for WinternitzPublicKey<D> {
    fn verify(&self, m: &[u8], sig: &Box<dyn OneTimeSignature>) -> Result<(), String> {
        match sig.as_any().downcast_ref::<WinternitzSignature>() {
            Some(sig) => WinternitzPublicKey::verify(self, m, sig),
            None => Err(String::from("Wrong one time signature?"))
        }
    }

    fn verify_arbitrary(&self, m: &[u8], sig: &Box<dyn OneTimeSignature>) -> Result<(), String> {
        match sig.as_any().downcast_ref::<WinternitzSignature>() {
            Some(sig) => WinternitzPublicKey::verify_arbitrary(self, m, sig),
            None => Err(String::from("Wrong one time signature?"))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::with_capacity(self.pk.len() * self.pk[0].len());
        self.pk.iter().for_each(|vec| ret.extend(vec));
        ret
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;
    use sha2::Sha512;

    const TEST_MESSAGE32: &[u8] = b"32 byte Winternitz test message!";
    const TEST_MESSAGE64: &[u8] = b"64 byte Winternitz test message, used for wider hash functions!!";
    const TEST_MESSAGE_AB: &[u8] = b"An arbitrary length message used to test Winternitz signing using digests";

    #[test]
    fn test_key_size_256() {
        let w = 256;
        let n = 32;
        let sk = WinternitzSecretKey::<Sha256>::new(w);
        let pk = WinternitzPublicKey::<Sha256>::new(&sk);

        let len = len(w, n);
        assert_eq!(sk.len(), len);
        assert_eq!(sk.sk[0].len(), n);

        //Check size of pk
        assert_eq!(pk.len(), len);
        assert_eq!(pk.pk[0].len(), n);
    }

    #[test]
    fn test_key_size_512() {
        let w = 256;
        let n = 64;
        let sk = WinternitzSecretKey::<Sha512>::new(w);
        let pk = WinternitzPublicKey::<Sha512>::new(&sk);

        let len = len(w, n);
        assert_eq!(sk.len(), len);
        assert_eq!(sk.sk[0].len(), n);

        //Check size of pk
        assert_eq!(pk.len(), len);
        assert_eq!(pk.pk[0].len(), n);
    }

    #[test]
    fn test_public_key() {
        let w = 256;
        let sk = WinternitzSecretKey::<Sha256>::new(w);
        let pk = WinternitzPublicKey::<Sha256>::new(&sk);

        let mut sk_i = Sha256::digest(&sk.sk[0]);
        // hash a value 254 times. 255 in total, since we already did it once
        for _ in 0..254 {
            sk_i = Sha256::digest(sk_i);
        }
        let pk_test = sk_i.to_vec();
        
        assert_eq!(pk_test, pk.pk[0])
    }

    #[test]
    fn test_sign_verify_big() {
        let w = 256;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);
        let PK = WinternitzPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        PK.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_medium() {
        let w = 16;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);
        let PK = WinternitzPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        PK.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_small() {
        let w = 4;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);
        let PK = WinternitzPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        PK.verify(TEST_MESSAGE32, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_arbitrary() {
        let w = 256;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);
        let PK = WinternitzPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign_arbitrary(TEST_MESSAGE_AB).unwrap();
        PK.verify_arbitrary(TEST_MESSAGE_AB, &sig).unwrap();
    }

    #[test]
    fn test_sign_verify_wrong_sig() {
        let w = 256;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);
        let PK = WinternitzPublicKey::<Sha256>::new(&SK);

        let mut sig = SK.sign(TEST_MESSAGE32).unwrap();
        sig.sig[17][6] ^= 1;
        let res = PK.verify(TEST_MESSAGE32, &sig);

        assert!(res.is_err());
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let w = 256;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);
        let PK = WinternitzPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        let new_message = b"This is a different message, so ";
        let res = PK.verify(new_message, &sig);

        assert!(res.is_err());
    }

    #[test]
    fn test_sign_wrong_message_size() {
        let w = 256;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);

        let sig = SK.sign(TEST_MESSAGE64);

        assert!(sig.is_err());
    }

    #[test]
    fn test_sign_already_used() {
        let w = 256;
        let mut SK = WinternitzSecretKey::<Sha256>::new(w);
        let PK = WinternitzPublicKey::<Sha256>::new(&SK);

        let sig = SK.sign(TEST_MESSAGE32).unwrap();
        PK.verify(TEST_MESSAGE32, &sig).unwrap();

        let res = SK.sign(TEST_MESSAGE32);

        assert!(res.is_err());
    }
}