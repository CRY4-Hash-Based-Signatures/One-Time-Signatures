use sha2::Digest;
use std::any::Any;

pub mod lamport;
pub mod winternitz;

pub use lamport::{LamportPublicKey, LamportSecretKey};
pub use winternitz::{WinternitzSecretKey, WinternitzPublicKey};

#[derive(Copy, Clone)]
pub enum OneTimeScheme {
    Lamport,
    Winternitz(usize),
}

pub trait OneTimeSignature: OneTimeSignatureToAny {}

pub trait OneTimeSignatureToAny: 'static {
    fn as_any(&self) -> &dyn Any;
}

impl<T: 'static> OneTimeSignatureToAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait OneTimeSecretKey<D> {
    fn sign(&mut self, m: &[u8]) -> Result<Box<dyn OneTimeSignature>, String>;
    fn sign_arbitrary(&mut self, m: &[u8]) -> Result<Box<dyn OneTimeSignature>, String>;
}
pub trait OneTimePublicKey<D> : OneTimePublicKeyClone<D>  {
    fn verify(&self, m: &[u8], sig: &Box<dyn OneTimeSignature>) -> Result<(), String>;
    fn verify_arbitrary(&self, m: &[u8], sig: &Box<dyn OneTimeSignature>) -> Result<(), String>;
    fn to_bytes(&self) -> Vec<u8>;
}

pub trait OneTimePublicKeyClone<D> {
    fn clone_box(&self) -> Box<dyn OneTimePublicKey<D>>;
}

impl<D, T> OneTimePublicKeyClone<D> for T 
where
    D: Digest,
    T: 'static + OneTimePublicKey<D> + Clone,
{
    fn clone_box(&self) -> Box<dyn OneTimePublicKey<D>> {
        Box::new(self.clone())
    }
}

impl<D: Digest> Clone for Box<dyn OneTimePublicKey<D>> {
    fn clone(&self) -> Box<dyn OneTimePublicKey<D>> {
        self.clone_box()
    }
}