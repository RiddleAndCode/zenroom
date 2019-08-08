extern crate libc;
extern crate ring;
extern crate untrusted;

use libc::c_uchar;
use ring::{rand, signature, signature::EcdsaKeyPair, signature::KeyPair};
use std::{ptr, slice};

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

#[inline]
fn ecdsa_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    signature::verify(
        &signature::ECDSA_P256_SHA256_FIXED,
        untrusted::Input::from(public),
        untrusted::Input::from(message),
        untrusted::Input::from(signature),
    )
    .is_ok()
}

#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum error_code {
    no_error,
}

#[no_mangle]
pub static RING_ECDSA_PRIVATE_LEN: usize = 138;

#[no_mangle]
pub static RING_ECDSA_PUBLIC_LEN: usize = 65;

#[no_mangle]
pub static RING_ECDSA_SIGNATURE_LEN: usize = 64;

#[no_mangle]
pub unsafe extern "C" fn rust_ring_ecdsa_generate_private(buf: *mut c_uchar) -> error_code {
    let sk = ecdsa_generate_private();
    ptr::copy_nonoverlapping(sk.as_ptr(), buf, RING_ECDSA_PRIVATE_LEN);
    error_code::no_error
}

#[no_mangle]
pub unsafe extern "C" fn rust_ring_ecdsa_public_from_private(
    private: *mut c_uchar,
    buf: *mut c_uchar,
) -> error_code {
    let sk = slice::from_raw_parts(private, RING_ECDSA_PRIVATE_LEN);
    let pk = ecdsa_public_from_private(sk);
    ptr::copy_nonoverlapping(pk.as_ptr(), buf, RING_ECDSA_PUBLIC_LEN);
    error_code::no_error
}

#[no_mangle]
pub unsafe extern "C" fn rust_ring_ecdsa_sign(
    private: *mut c_uchar,
    msg: *mut c_uchar,
    msg_len: usize,
    buf: *mut c_uchar,
) -> error_code {
    let message = slice::from_raw_parts(msg, msg_len);
    let sk = slice::from_raw_parts(private, RING_ECDSA_PRIVATE_LEN);
    let signature = ecdsa_sign(sk, message);
    ptr::copy_nonoverlapping(signature.as_ptr(), buf, RING_ECDSA_PUBLIC_LEN);
    error_code::no_error
}

#[no_mangle]
pub unsafe extern "C" fn rust_ring_ecdsa_verify(
    public: *mut c_uchar,
    msg: *mut c_uchar,
    msg_len: usize,
    signature: *mut c_uchar,
) -> bool {
    let pk = slice::from_raw_parts(public, RING_ECDSA_PUBLIC_LEN);
    let message = slice::from_raw_parts(msg, msg_len);
    let sig = slice::from_raw_parts(signature, RING_ECDSA_SIGNATURE_LEN);
    ecdsa_verify(pk, message, sig)
}
