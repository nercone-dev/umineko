use umineko_crypto_hqc::{GF256, ReedMuller, ReedSolomon};

#[test]
fn field_laws() {
    let field = GF256::new();
    assert_eq!(field.multiply(0, 5), 0);
    assert_eq!(field.multiply(1, 5), 5);
    assert_eq!(field.multiply(2, 2), 4);
    assert_eq!(field.multiply(0x80, 2), 0x1D);
    for value in 1..=255u8 {
        assert_eq!(field.multiply(value, field.inverse(value)), 1, "{value}");
        assert_eq!(field.power(field.logarithm(value)), value, "{value}");
    }
    assert_eq!(field.evaluate(&[1, 1], 1), 0);
    assert_eq!(field.evaluate(&[3, 0, 1], 2), 7);
}

#[test]
fn solomon_corrects() {
    for (blocks, message, corrections) in [(46, 16, 15), (56, 24, 16), (90, 32, 29)] {
        let code = ReedSolomon::new(blocks, message, corrections);
        assert_eq!(code.generator().len(), 2 * corrections + 1);
        assert_eq!(code.parity(), 2 * corrections);
        let data: Vec<u8> = (0..message).map(|index| (index * 7 + 1) as u8).collect();
        let codeword = code.encode(&data);
        assert_eq!(codeword.len(), blocks);
        assert_eq!(&codeword[code.parity()..], &data[..]);
        assert!(code.syndromes(&codeword).iter().all(|value| *value == 0));
        assert_eq!(code.decode(&codeword), data);
        for count in 1..=corrections {
            let mut broken = codeword.clone();
            for index in 0..count {
                broken[(index * 3 + 1) % blocks] ^= ((index + 1) * 37) as u8;
            }
            assert_eq!(code.decode(&broken), data, "{blocks} {count}");
        }
    }
}

#[test]
fn muller_corrects() {
    for multiplicity in [3, 5] {
        let code = ReedMuller::new(multiplicity);
        let data: Vec<u8> = (0..46).map(|index| (index * 5 + 3) as u8).collect();
        let codeword = code.encode(&data);
        assert_eq!(codeword.len(), data.len() * multiplicity * 16);
        assert_eq!(code.decode(&codeword), data);
        let mut broken = codeword.clone();
        for (index, byte) in broken.iter_mut().enumerate() {
            if index % 23 == 0 {
                *byte ^= 1 << (index % 8);
            }
        }
        assert_eq!(code.decode(&broken), data, "{multiplicity}");
    }
}
