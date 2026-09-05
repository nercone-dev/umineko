use umineko_math::{Edwards, Integer, Ladder, Modulus, Prime, Weierstrass};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn integer(text: &str) -> Integer {
    Integer::from_hex(text).unwrap()
}

#[test]
fn integer_bytes() {
    assert_eq!(Integer::from_bytes(&[0x01, 0x02, 0x03]).bytes(), [0x01, 0x02, 0x03]);
    assert_eq!(Integer::from_bytes(&[0x00, 0x00, 0xff]).bytes(), [0xff]);
    assert_eq!(Integer::from_bytes(&[]).bytes(), []);
    assert_eq!(Integer::from_u64(0x1234).to_bytes(4), [0x00, 0x00, 0x12, 0x34]);
    assert_eq!(integer("0102030405060708090a").bytes(), hex("0102030405060708090a"));
    assert_eq!(integer("ffffffffffffffffff").bits(), 72);
    assert!(integer("8000000000000000").bit(63));
    assert!(!integer("8000000000000000").bit(62));
}

#[test]
fn integer_arithmetic() {
    let (left, right) = (integer("fedcba9876543210fedcba9876543210"), integer("123456789abcdef0"));
    assert_eq!(left.add(&right).subtract(&right), left);
    assert_eq!(left.multiply(&right).divide(&left).unwrap().0, right);
    let (quotient, remainder) = left.divide(&right).unwrap();
    assert_eq!(quotient.multiply(&right).add(&remainder), left);
    assert!(remainder.compare(&right) == core::cmp::Ordering::Less);
    assert_eq!(left.shift_left(129).shift_right(129), left);
    assert_eq!(left.subtract(&left), Integer::zero());
    assert_eq!(left.negate().add(&left), Integer::zero());
    assert_eq!(Integer::from_u64(12).gcd(&Integer::from_u64(18)), Integer::from_u64(6));
    let (divisor, first, second) = Integer::from_u64(240).extended_gcd(&Integer::from_u64(46));
    assert_eq!(divisor, Integer::from_u64(2));
    assert_eq!(Integer::from_u64(240).multiply(&first).add(&Integer::from_u64(46).multiply(&second)), divisor);
}

#[test]
fn integer_division() {
    for (left, right) in [("ffffffffffffffffffffffffffffffff", "ffffffffffffffff"), ("100000000000000000000000000000000", "3"), ("1", "2"), ("abcdef0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba98")] {
        let (left, right) = (integer(left), integer(right));
        let (quotient, remainder) = left.divide(&right).unwrap();
        assert_eq!(quotient.multiply(&right).add(&remainder), left, "{left} / {right}");
        assert!(remainder.compare(&right) == core::cmp::Ordering::Less);
    }
    assert!(Integer::one().divide(&Integer::zero()).is_none());
}

#[test]
fn modulus_arithmetic() {
    let modulus = Modulus::new(&Integer::from_u64(1_000_003)).unwrap();
    assert_eq!(modulus.exponentiate(&Integer::from_u64(2), &Integer::from_u64(10)), Integer::from_u64(1024));
    assert_eq!(modulus.exponentiate(&Integer::from_u64(7), &Integer::from_u64(1_000_002)), Integer::one());
    let value = modulus.residue(&Integer::from_u64(12345));
    let inverse = modulus.inverse(&value).unwrap();
    assert_eq!(modulus.integer(&modulus.multiply(&value, &inverse)), Integer::one());
    let square = modulus.square(&value);
    let root = modulus.square_root(&square).unwrap();
    assert!(root == value || root == modulus.negate(&value));
    assert_eq!(modulus.integer(&modulus.add(&value, &modulus.negate(&value))), Integer::zero());
}

#[test]
fn modulus_exponentiation() {
    let modulus = Modulus::new(&integer("c1eb1a4e0d0d5b7c1d5f8ae0b0f9f26d0e6b0f3b1a5f9e3d8c7b6a5948372615c1eb1a4e0d0d5b7c1d5f8ae0b0f9f26d0e6b0f3b1a5f9e3d8c7b6a594837261b")).unwrap();
    let base = integer("0123456789abcdef0123456789abcdef");
    let one = modulus.exponentiate(&base, &Integer::zero());
    assert_eq!(one, Integer::one());
    let square = modulus.exponentiate(&base, &Integer::from_u64(2));
    assert_eq!(square, base.multiply(&base).remainder(modulus.modulus()).unwrap());
    let cube = modulus.exponentiate(&base, &Integer::from_u64(3));
    assert_eq!(cube, square.multiply(&base).remainder(modulus.modulus()).unwrap());
}

#[test]
fn prime_recognition() {
    assert!(Prime::probable(&Integer::from_u64(2), Prime::ROUNDS));
    assert!(Prime::probable(&Integer::from_u64(65537), Prime::ROUNDS));
    assert!(!Prime::probable(&Integer::from_u64(65536), Prime::ROUNDS));
    assert!(!Prime::probable(&Integer::from_u64(1_000_001), Prime::ROUNDS));
    assert!(Prime::probable(&integer("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43"), Prime::ROUNDS));
    assert!(!Prime::probable(&integer("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff61"), Prime::ROUNDS));
}

#[test]
fn weierstrass_curves() {
    for curve in [Weierstrass::secp256r1(), Weierstrass::secp384r1(), Weierstrass::secp521r1(), Weierstrass::secp256k1()] {
        let generator = curve.generator();
        assert!(curve.contains(&generator), "{curve}");
        let order = curve.order().modulus().clone();
        assert!(curve.multiply(&generator, &order).is_identity(), "{curve}");
        let last = curve.multiply(&generator, &order.subtract(&Integer::one()));
        assert_eq!(curve.affine(&last).unwrap().0, curve.affine(&generator).unwrap().0, "{curve}");
        let doubled = curve.double(&generator);
        assert_eq!(curve.affine(&doubled), curve.affine(&curve.multiply(&generator, &Integer::from_u64(2))), "{curve}");
        let sum = curve.add(&doubled, &generator);
        assert_eq!(curve.affine(&sum), curve.affine(&curve.multiply(&generator, &Integer::from_u64(3))), "{curve}");
        assert!(curve.add(&generator, &curve.negate(&generator)).is_identity(), "{curve}");
        assert!(curve.add(&generator, &curve.identity()) == curve.identity() || curve.affine(&curve.add(&generator, &curve.identity())) == curve.affine(&generator), "{curve}");
        let encoded = curve.encode(&sum, false);
        assert_eq!(curve.affine(&curve.decode(&encoded).unwrap()), curve.affine(&sum), "{curve}");
        let compressed = curve.encode(&sum, true);
        assert_eq!(curve.affine(&curve.decode(&compressed).unwrap()), curve.affine(&sum), "{curve}");
    }
}

#[test]
fn weierstrass_vectors() {
    let curve = Weierstrass::secp256r1();
    let (x, y) = curve.affine(&curve.multiply(&curve.generator(), &Integer::from_u64(2))).unwrap();
    assert_eq!(x, integer("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"));
    assert_eq!(y, integer("07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"));
    let (x, y) = curve.affine(&curve.multiply(&curve.generator(), &Integer::from_u64(3))).unwrap();
    assert_eq!(x, integer("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"));
    assert_eq!(y, integer("8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"));
    let curve = Weierstrass::secp256k1();
    let (x, y) = curve.affine(&curve.multiply(&curve.generator(), &Integer::from_u64(2))).unwrap();
    assert_eq!(x, integer("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"));
    assert_eq!(y, integer("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"));
}

#[test]
fn edwards_curves() {
    for curve in [Edwards::ed25519(), Edwards::ed448()] {
        let generator = curve.generator();
        assert!(curve.contains(&generator), "{curve}");
        let order = curve.order().modulus().clone();
        assert!(curve.equals(&curve.multiply(&generator, &order), &curve.identity()), "{curve}");
        assert!(!curve.equals(&curve.double(&generator), &curve.identity()), "{curve}");
        assert!(curve.equals(&curve.add(&generator, &curve.negate(&generator)), &curve.identity()), "{curve}");
        assert!(curve.equals(&curve.double(&generator), &curve.multiply(&generator, &Integer::from_u64(2))), "{curve}");
        let encoded = curve.encode(&generator);
        assert!(curve.equals(&curve.decode(&encoded).unwrap(), &generator), "{curve}");
        assert_eq!(curve.encode(&curve.decode(&encoded).unwrap()), encoded, "{curve}");
        assert_eq!(curve.encode(&curve.identity()), curve.encode(&curve.multiply(&generator, &order)), "{curve}");
    }
}

#[test]
fn ladder_vectors() {
    let curve = Ladder::x25519();
    let output = curve.multiply(&hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), &hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).unwrap();
    assert_eq!(output, hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    let output = curve.multiply(&hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"), &hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")).unwrap();
    assert_eq!(output, hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
    let output = curve.multiply_base(&curve.base()).unwrap();
    assert_eq!(output, hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
    let curve = Ladder::x448();
    let scalar = hex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
    let point = hex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
    let output = curve.multiply(&scalar, &point).unwrap();
    assert_eq!(output, hex("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"));
}

#[test]
fn ladder_exchange() {
    for curve in [Ladder::x25519(), Ladder::x448()] {
        let mut first = alloc_seed(curve.size(), 0x11);
        let mut second = alloc_seed(curve.size(), 0x22);
        curve.clamp(&mut first);
        curve.clamp(&mut second);
        let public_first = curve.multiply_base(&first).unwrap();
        let public_second = curve.multiply_base(&second).unwrap();
        assert_eq!(curve.multiply(&first, &public_second).unwrap(), curve.multiply(&second, &public_first).unwrap(), "{curve}");
    }
}

fn alloc_seed(length: usize, value: u8) -> Vec<u8> {
    (0..length).map(|index| value.wrapping_add(index as u8)).collect()
}
