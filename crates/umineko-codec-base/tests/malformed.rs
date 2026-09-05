use umineko_codec_base::{Base16, Base32, Base32Alphabet, Base58, Base58Alphabet, Base64, Base64Alphabet, Base85, Base85Alphabet};

/// Every decoder reads untrusted text, so broken text must come back as an error rather than a panic.
#[test]
fn malformed_text_is_refused_without_panicking() {
    let alphabet: Vec<char> = "AZaz09+/=-_.~!#$%&()*;<>?@^`{|}~ \t\n\u{00E9}".chars().collect();
    for seed in 0..4000usize {
        let length = seed % 17;
        let text: String = (0..length).map(|index| alphabet[(seed * 7 + index * 13) % alphabet.len()]).collect();
        let _ = Base16::default().decode(&text);
        for padding in [true, false] {
            for value in [Base32Alphabet::Standard, Base32Alphabet::ExtendedHex, Base32Alphabet::Crockford] {
                let _ = Base32 { alphabet: value, padding }.decode(&text);
            }
            for value in [Base64Alphabet::Standard, Base64Alphabet::URL] {
                let _ = Base64 { alphabet: value, padding }.decode(&text);
            }
            for value in [Base58Alphabet::Bitcoin, Base58Alphabet::Ripple, Base58Alphabet::Flickr] {
                let _ = Base58 { alphabet: value, padding }.decode(&text);
            }
            for value in [Base85Alphabet::ASCII85, Base85Alphabet::Z85, Base85Alphabet::RFC1924] {
                let _ = Base85 { alphabet: value, padding }.decode(&text);
            }
        }
    }
}
