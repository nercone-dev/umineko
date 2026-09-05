use umineko_codec_base::{Base16, Base32, Base32Alphabet, Base58, Base58Alphabet, Base64, Base64Alphabet, Base85, Base85Alphabet, BaseError};

fn base32(alphabet: Base32Alphabet, padding: bool) -> Base32 {
    Base32 { alphabet, padding }
}

fn base64(alphabet: Base64Alphabet, padding: bool) -> Base64 {
    Base64 { alphabet, padding }
}

fn base85(alphabet: Base85Alphabet, padding: bool) -> Base85 {
    Base85 { alphabet, padding }
}

#[test]
fn base16_matches_rfc_4648() {
    let codec = Base16 { uppercase: true };
    for (data, text) in [("", ""), ("f", "66"), ("fo", "666F"), ("foo", "666F6F"), ("foob", "666F6F62"), ("fooba", "666F6F6261"), ("foobar", "666F6F626172")] {
        assert_eq!(codec.encode(data.as_bytes()), text);
        assert_eq!(codec.decode(text).unwrap(), data.as_bytes());
        assert_eq!(codec.encoded_len(data.len()), text.len());
        assert_eq!(codec.decoded_len(text.len()), data.len());
    }
}

#[test]
fn base16_reads_both_cases_and_rejects_the_rest() {
    let codec = Base16::default();
    assert_eq!(codec.encode(b"foobar"), "666f6f626172");
    assert_eq!(codec.decode("666F6f626172").unwrap(), b"foobar");
    assert_eq!(codec.decode("666"), Err(BaseError::Length));
    assert_eq!(codec.decode("6g"), Err(BaseError::Alphabet));
}

#[test]
fn base32_matches_rfc_4648() {
    let codec = base32(Base32Alphabet::Standard, true);
    for (data, text) in [("", ""), ("f", "MY======"), ("fo", "MZXQ===="), ("foo", "MZXW6==="), ("foob", "MZXW6YQ="), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI======")] {
        assert_eq!(codec.encode(data.as_bytes()), text);
        assert_eq!(codec.decode(text).unwrap(), data.as_bytes());
        assert_eq!(codec.encoded_len(data.len()), text.len());
    }
}

#[test]
fn base32_extended_hex_matches_rfc_4648() {
    let codec = base32(Base32Alphabet::ExtendedHex, true);
    for (data, text) in [("", ""), ("f", "CO======"), ("fo", "CPNG===="), ("foo", "CPNMU==="), ("foob", "CPNMUOG="), ("fooba", "CPNMUOJ1"), ("foobar", "CPNMUOJ1E8======")] {
        assert_eq!(codec.encode(data.as_bytes()), text);
        assert_eq!(codec.decode(text).unwrap(), data.as_bytes());
    }
}

#[test]
fn base32_without_padding_round_trips() {
    let codec = base32(Base32Alphabet::Standard, false);
    for data in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
        let text = codec.encode(data.as_bytes());
        assert!(!text.contains('='));
        assert_eq!(codec.encoded_len(data.len()), text.len());
        assert_eq!(codec.decode(&text).unwrap(), data.as_bytes());
    }
}

#[test]
fn base32_rejects_broken_padding() {
    let codec = base32(Base32Alphabet::Standard, true);
    assert_eq!(codec.decode("MY====="), Err(BaseError::Padding));
    assert_eq!(codec.decode("MZXW6Y=="), Err(BaseError::Padding));
    assert_eq!(codec.decode("MZXW6YTBO="), Err(BaseError::Padding));
}

#[test]
fn base32_crockford_reads_confusable_symbols() {
    let codec = base32(Base32Alphabet::Crockford, false);
    let text = codec.encode(b"foobar");
    assert_eq!(codec.decode(&text).unwrap(), b"foobar");
    assert_eq!(codec.decode("CSQPYRK1E8").unwrap(), codec.decode("csqpyrk1e8").unwrap());
    assert_eq!(codec.decode("CSQPYRK1E8").unwrap(), codec.decode("CS-QP-YR-K1-E8").unwrap());
    assert_eq!(codec.decode("1").unwrap_err(), BaseError::Length);
    assert_eq!(codec.decode("I0").unwrap(), codec.decode("10").unwrap());
    assert_eq!(codec.decode("LO").unwrap(), codec.decode("10").unwrap());
}

#[test]
fn base64_matches_rfc_4648() {
    let codec = base64(Base64Alphabet::Standard, true);
    for (data, text) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
        assert_eq!(codec.encode(data.as_bytes()), text);
        assert_eq!(codec.decode(text).unwrap(), data.as_bytes());
        assert_eq!(codec.encoded_len(data.len()), text.len());
    }
}

#[test]
fn base64_url_swaps_the_last_two_symbols() {
    let data = [0xFB, 0xFF, 0xBF];
    assert_eq!(base64(Base64Alphabet::Standard, true).encode(&data), "+/+/");
    assert_eq!(base64(Base64Alphabet::URL, true).encode(&data), "-_-_");
    assert_eq!(base64(Base64Alphabet::URL, true).decode("-_-_").unwrap(), data);
    assert_eq!(base64(Base64Alphabet::URL, true).decode("+/+/"), Err(BaseError::Alphabet));
}

#[test]
fn base64_without_padding_round_trips() {
    let codec = base64(Base64Alphabet::Standard, false);
    for data in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
        let text = codec.encode(data.as_bytes());
        assert!(!text.contains('='));
        assert_eq!(codec.encoded_len(data.len()), text.len());
        assert_eq!(codec.decode(&text).unwrap(), data.as_bytes());
    }
}

#[test]
fn base64_rejects_broken_padding() {
    let codec = base64(Base64Alphabet::Standard, true);
    assert_eq!(codec.decode("Zg="), Err(BaseError::Padding));
    assert_eq!(codec.decode("Zg==="), Err(BaseError::Padding));
    assert_eq!(codec.decode("Z==="), Err(BaseError::Padding));
}

#[test]
fn base58_matches_the_bitcoin_alphabet() {
    let codec = Base58::default();
    assert_eq!(codec.encode(b"Hello World!"), "2NEpo7TZRRrLZSi2U");
    assert_eq!(codec.decode("2NEpo7TZRRrLZSi2U").unwrap(), b"Hello World!");
    assert_eq!(codec.encode(b""), "");
    assert_eq!(codec.encode(&[0, 0, 0]), "111");
    assert_eq!(codec.decode("111").unwrap(), [0, 0, 0]);
    assert_eq!(codec.encode(&[0, 0, 0, 1]), "1112");
    assert_eq!(codec.decode("1112").unwrap(), [0, 0, 0, 1]);
    assert_eq!(codec.decode("0"), Err(BaseError::Alphabet));
}

#[test]
fn base58_alphabets_carry_the_same_value() {
    let data = b"the quick brown fox";
    for alphabet in [Base58Alphabet::Bitcoin, Base58Alphabet::Ripple, Base58Alphabet::Flickr] {
        let codec = Base58 { alphabet, padding: true };
        let text = codec.encode(data);
        assert!(text.len() <= codec.encoded_len(data.len()));
        assert_eq!(codec.decode(&text).unwrap(), data);
    }
}

#[test]
fn base85_matches_ascii85() {
    let codec = base85(Base85Alphabet::ASCII85, true);
    assert_eq!(codec.encode(b"Man "), "9jqo^");
    assert_eq!(codec.decode("9jqo^").unwrap(), b"Man ");
    assert_eq!(codec.encode(&[0, 0, 0, 0]), "z");
    assert_eq!(codec.decode("z").unwrap(), [0, 0, 0, 0]);
    for data in ["", "a", "ab", "abc", "abcd", "abcde", "sure"] {
        let text = codec.encode(data.as_bytes());
        assert_eq!(codec.decode(&text).unwrap(), data.as_bytes());
    }
    assert_eq!(codec.decode("9"), Err(BaseError::Length));
    assert_eq!(codec.decode("9j~"), Err(BaseError::Alphabet));
}

#[test]
fn base85_matches_z85() {
    let codec = base85(Base85Alphabet::Z85, false);
    assert_eq!(codec.encode(&[0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]), "HelloWorld");
    assert_eq!(codec.decode("HelloWorld").unwrap(), [0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]);
    assert_eq!(codec.decode("Hello"), Ok([0x86, 0x4F, 0xD2, 0x6F].to_vec()));
    assert_eq!(codec.decode("Hell"), Err(BaseError::Length));
}

#[test]
fn base85_matches_rfc_1924() {
    let codec = base85(Base85Alphabet::RFC1924, true);
    let address = [0x10, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A];
    assert_eq!(codec.encode(&address), "4)+k&C#VzJ4br>0wv%Yp");
    assert_eq!(codec.decode("4)+k&C#VzJ4br>0wv%Yp").unwrap(), address);
    for data in ["", "a", "ab", "abc", "abcd", "abcde"] {
        let text = codec.encode(data.as_bytes());
        assert_eq!(text.len(), codec.encoded_len(data.len()));
        assert_eq!(codec.decode(&text).unwrap(), data.as_bytes());
    }
}
