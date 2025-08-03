use chacha20poly1305::{aead::Aead, aead::AeadInOut, legacy::ChaCha20Poly1305Legacy, KeyInit};
use sodiumoxide::crypto::aead::chacha20poly1305::{self as sodiumoxidecipher, Key, Nonce, Tag};

fn main() {
    let key = b"qweruiodskgdfvbskdjhfvbksjdhfbvk";
    let nonce = b"ihuoruiw";
    let msg = b"01hello world!23";
    let ad = b"blub";

    roundtrip_rc_to_sodium(*key, *nonce, msg, ad);
    roundtrip_sodium_to_rc(*key, *nonce, msg, ad);
}

fn roundtrip_rc_to_sodium(key: [u8; 32], nonce: [u8; 8], msg: &[u8], ad: &[u8]) {
    let mut rustbuf = msg.to_owned();
    let rust = ChaCha20Poly1305Legacy::new(&key.into());
    let rusttag = rust
        .encrypt_inout_detached(&nonce.into(), ad, rustbuf.as_mut_slice().into())
        .unwrap();

    let rustcipherhex = hex::encode(&rustbuf);
    let rusttaghex = hex::encode(&rusttag);

    println!("{rustcipherhex}{rusttaghex}");

    sodiumoxidecipher::open_detached(
        &mut rustbuf,
        Some(ad),
        &Tag::from_slice(&rusttag).unwrap(),
        &Nonce::from_slice(&nonce).unwrap(),
        &Key::from_slice(&key).unwrap(),
    )
    .unwrap();

    assert!(rustbuf == msg);

    let rustplainstring = core::str::from_utf8(&rustbuf).unwrap();
    println!("{rustplainstring}");
}

fn roundtrip_sodium_to_rc(key: [u8; 32], nonce: [u8; 8], msg: &[u8], ad: &[u8]) {
    let mut sodiumbuf = msg.to_owned();

    let sodiumtag = sodiumoxidecipher::seal_detached(
        &mut sodiumbuf,
        Some(ad),
        &Nonce::from_slice(&nonce).unwrap(),
        &Key::from_slice(&key).unwrap(),
    );

    let sodiumcipherhex = hex::encode(&sodiumbuf);
    let sodiumtaghex = hex::encode(&sodiumtag);

    println!("{sodiumcipherhex}{sodiumtaghex}");

    let rust = ChaCha20Poly1305Legacy::new(&key.into());
    rust.decrypt_inout_detached(
        &nonce.into(),
        ad,
        sodiumbuf.as_mut_slice().into(),
        &sodiumtag.0.into(),
    )
    .unwrap();

    let sodiumplainstring = core::str::from_utf8(&sodiumbuf).unwrap();
    println!("{sodiumplainstring}");
}
