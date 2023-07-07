use aes_gcm::aead::{generic_array::GenericArray};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm,
};

use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};

#[inline]
pub fn aes_128_gcm(key: &[u8; 16], nonce: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = Aes128Gcm::new(key);
    cipher.encrypt(nonce, payload).unwrap()
}

#[inline]
pub fn aes_256_gcm(key: &[u8; 32], nonce: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    cipher.encrypt(nonce, payload).unwrap()
}

#[inline]
pub fn aes_128_gcm_siv(key: &[u8; 16], nonce: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = Aes128GcmSiv::new(key);
    cipher.encrypt(nonce, payload).unwrap()
}

#[inline]
pub fn aes_256_gcm_siv(key: &[u8; 32], nonce: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = Aes256GcmSiv::new(key);
    cipher.encrypt(nonce, payload).unwrap()
}
