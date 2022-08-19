use chacha20poly1305::{
    aead::Aead, chacha20poly1305legacy::ChaCha20Poly1305Legacy, AeadInPlace, KeyInit,
};
use sodiumoxide::crypto::aead::chacha20poly1305::{self as sodiumoxidecipher, Key, Nonce, Tag};

fn main() {
    let mykey = b"qweruiodskgdfvbskdjhfvbksjdhfbvk";
    let mynonce = b"ihuoruiw";
    let myplain = b"01hello world!23";
    let myad = b"blub";

    let mut rustbuf = myplain.to_owned();
    let rust = ChaCha20Poly1305Legacy::new(mykey.into());
    let rusttag = rust
        .encrypt_in_place_detached(mynonce.into(), myad.as_slice(), rustbuf.as_mut_slice())
        .unwrap();

    let rustcipherhex = hex::encode(rustbuf);
    let rusttaghex = hex::encode(rusttag);

    println!("{rustcipherhex}{rusttaghex}");

    let mut sodiumbuf = myplain.to_owned();

    let sodiumtag = sodiumoxidecipher::seal_detached(
        &mut sodiumbuf,
        Some(myad),
        &Nonce::from_slice(mynonce).unwrap(),
        &Key::from_slice(mykey).unwrap(),
    );

    let sodiumcipherhex = hex::encode(sodiumbuf);
    let sodiumtaghex = hex::encode(sodiumtag);

    println!("{sodiumcipherhex}{sodiumtaghex}");

    sodiumoxidecipher::open_detached(
        &mut rustbuf,
        Some(myad),
        &Tag::from_slice(&rusttag).unwrap(),
        &Nonce::from_slice(mynonce).unwrap(),
        &Key::from_slice(mykey).unwrap(),
    )
    .unwrap();
    let rustplainstring = core::str::from_utf8(&rustbuf).unwrap();
    println!("{rustplainstring}");

    rust.decrypt_in_place_detached(
        mynonce.into(),
        myad.as_slice(),
        sodiumbuf.as_mut_slice(),
        sodiumtag.0.as_ref().into(),
    )
    .unwrap();

    let sodiumplainstring = core::str::from_utf8(&sodiumbuf).unwrap();
    println!("{sodiumplainstring}");
}
