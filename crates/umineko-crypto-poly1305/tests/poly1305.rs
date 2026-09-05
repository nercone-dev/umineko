use umineko_crypto_poly1305::{Poly1305, Poly1305Error};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn key(text: &str) -> [u8; 32] {
    let mut key = [0; 32];
    key.copy_from_slice(&hex(text));
    key
}

fn tag(text: &str) -> [u8; 16] {
    let mut tag = [0; 16];
    tag.copy_from_slice(&hex(text));
    tag
}

#[test]
fn vectors() {
    let secret = key("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    assert_eq!(Poly1305::tag(&secret, b"Cryptographic Forum Research Group"), tag("a8061dc1305136c6c22b8baf0c0127a9"));
    assert_eq!(Poly1305::tag(&[0; 32], &[0; 64]), [0; 16]);
    let secret = key("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e");
    assert_eq!(Poly1305::tag(&secret, &hex("416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f")), tag("36e5f6b5c5e06070f0efca96227a863e"));
    let secret = key("02000000000000000000000000000000ffffffffffffffffffffffffffffffff");
    assert_eq!(Poly1305::tag(&secret, &hex("02000000000000000000000000000000")), tag("03000000000000000000000000000000"));
    let secret = key("0100000000000000000000000000000000000000000000000000000000000000");
    assert_eq!(Poly1305::tag(&secret, &hex("fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000")), tag("05000000000000000000000000000000"));
}

#[test]
fn streaming() {
    let secret = key("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let message = b"Cryptographic Forum Research Group";
    for split in 0..message.len() {
        let mut mac = Poly1305::new(&secret);
        mac.update(&message[..split]);
        mac.update(&message[split..]);
        assert_eq!(mac.finalize(), tag("a8061dc1305136c6c22b8baf0c0127a9"), "{split}");
    }
    let mut mac = Poly1305::new(&secret);
    for byte in message {
        mac.update(&[*byte]);
    }
    assert_eq!(mac.finalize(), tag("a8061dc1305136c6c22b8baf0c0127a9"));
}

#[test]
fn verification() {
    let secret = key("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let mut mac = Poly1305::new(&secret);
    mac.update(b"Cryptographic Forum Research Group");
    assert_eq!(mac.clone().verify(&tag("a8061dc1305136c6c22b8baf0c0127a9")), Ok(()));
    assert_eq!(mac.verify(&tag("a8061dc1305136c6c22b8baf0c0127a8")), Err(Poly1305Error::Authentication));
}
