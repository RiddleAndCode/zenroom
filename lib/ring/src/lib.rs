extern crate libc;
extern crate ring;
extern crate untrusted;

use libc::{c_int, c_uchar};
use ring::{rand, signature, signature::EcdsaKeyPair, signature::KeyPair};
use std::ptr;

#[inline]
fn ecdsa_generate_private() -> Vec<u8> {
    let rng = rand::SystemRandom::new();
    let doc =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    doc.as_ref().to_vec()
}

#[inline]
fn ecdsa_keypair_from_private(private: &[u8]) -> EcdsaKeyPair {
    EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        untrusted::Input::from(private),
    )
    .unwrap()
}

#[inline]
fn ecdsa_public_from_private(private: &[u8]) -> Vec<u8> {
    ecdsa_keypair_from_private(private)
        .public_key()
        .as_ref()
        .to_vec()
}

#[inline]
fn ecdsa_sign(private: &[u8], message: &[u8]) -> Vec<u8> {
    let rng = rand::SystemRandom::new();
    let key_pair = ecdsa_keypair_from_private(private);
    key_pair
        .sign(&rng, untrusted::Input::from(message))
        .unwrap()
        .as_ref()
        .to_vec()
}

#[no_mangle]
pub static RING_ECDSA_PRIVATE_LEN: c_int = 138;

#[no_mangle]
pub static RING_ECDSA_PUBLIC_LEN: c_int = 65;

#[no_mangle]
pub static RING_ECDSA_SIGNATURE_LEN: c_int = 64;

#[no_mangle]
pub unsafe extern "C" fn rust_ring_ecdsa_generate_private(buf: *mut c_uchar) -> c_int {
    let sk = ecdsa_generate_private();
    ptr::copy_nonoverlapping(sk.as_ptr(), buf, RING_ECDSA_PRIVATE_LEN as usize);
    0
}
