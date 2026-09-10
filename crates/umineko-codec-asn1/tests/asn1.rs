use umineko_codec_asn1::{ASN1Class, ASN1Element, ASN1Encoding, ASN1Error, ASN1ObjectIdentifier, ASN1Tag, ASN1UniversalTag, ASN1Value};

const UNIVERSAL_TAGS: &[(u32, &str)] = &[
    (1, "BOOLEAN"),
    (2, "INTEGER"),
    (3, "BIT STRING"),
    (4, "OCTET STRING"),
    (5, "NULL"),
    (6, "OBJECT IDENTIFIER"),
    (7, "ObjectDescriptor"),
    (8, "EXTERNAL"),
    (9, "REAL"),
    (10, "ENUMERATED"),
    (11, "EMBEDDED PDV"),
    (12, "UTF8String"),
    (13, "RELATIVE-OID"),
    (14, "TIME"),
    (16, "SEQUENCE"),
    (17, "SET"),
    (18, "NumericString"),
    (19, "PrintableString"),
    (20, "TeletexString"),
    (21, "VideotexString"),
    (22, "IA5String"),
    (23, "UTCTime"),
    (24, "GeneralizedTime"),
    (25, "GraphicString"),
    (26, "VisibleString"),
    (27, "GeneralString"),
    (28, "UniversalString"),
    (29, "CHARACTER STRING"),
    (30, "BMPString"),
    (31, "DATE"),
    (32, "TIME-OF-DAY"),
    (33, "DATE-TIME"),
    (34, "DURATION"),
    (35, "OID-IRI"),
    (36, "RELATIVE-OID-IRI"),
];

#[test]
fn universal_tags_follow_x680_table1() {
    assert_eq!(ASN1UniversalTag::ALL.len(), UNIVERSAL_TAGS.len());
    for &(number, name) in UNIVERSAL_TAGS {
        let tag = ASN1UniversalTag::from_number(number).unwrap_or_else(|| panic!("{number} {name} is missing"));
        assert_eq!(tag.as_str(), name);
        assert_eq!(ASN1UniversalTag::from_name(name), Some(tag));
    }
    for number in [0, 15, 37, 1000] {
        assert_eq!(ASN1UniversalTag::from_number(number), None, "{number}");
    }
}

#[test]
fn tag_classes_follow_x690_table1() {
    for (number, name) in [(0, "Universal"), (1, "Application"), (2, "Context-specific"), (3, "Private")] {
        let class = ASN1Class::from_number(number).unwrap();
        assert_eq!(class.as_str(), name);
        assert_eq!(ASN1Class::from_name(name), Some(class));
    }
    assert_eq!(ASN1Class::ALL.len(), 4);
    assert_eq!(ASN1Class::from_number(4), None);
}

#[test]
fn cer_and_der_are_the_canonical_encodings_by_x690() {
    assert!(!ASN1Encoding::BER.canonical());
    assert!(ASN1Encoding::CER.canonical());
    assert!(ASN1Encoding::DER.canonical());
    for encoding in ASN1Encoding::ALL {
        assert_eq!(ASN1Encoding::from_name(encoding.as_str()), Some(encoding));
    }
}

#[test]
fn object_identifier_arcs_follow_x660_and_x690() {
    for arcs in [&[0, 0][..], &[0, 39], &[1, 0], &[1, 39], &[2, 40], &[2, 100, 3], &[1, 2, 840, 113549]] {
        assert_eq!(ASN1ObjectIdentifier::new(arcs).map(|identifier| identifier.arcs().to_vec()), Ok(arcs.to_vec()), "{arcs:?}");
    }
    for arcs in [&[][..], &[1], &[3, 0], &[0, 40], &[1, 40]] {
        assert_eq!(ASN1ObjectIdentifier::new(arcs), Err(ASN1Error::ObjectIdentifier), "{arcs:?}");
    }
}

#[test]
fn object_identifiers_use_the_numericoid_notation_of_rfc4512() {
    for text in ["1.2.840.113549.1.1.11", "1.0.14888.3.0.7", "1.2.156.10197.1.302.1", "2.100.3", "0.0"] {
        assert_eq!(ASN1ObjectIdentifier::parse(text).map(|identifier| identifier.to_string()), Ok(text.to_string()));
    }
    assert_eq!(ASN1ObjectIdentifier::parse("1.2.840").unwrap().arcs(), &[1, 2, 840]);
    for text in ["", "1", "1.", ".1", "1..2", "1.02", "01.2", "+1.2", "1.-2", "1.a", "3.1", "1.40"] {
        assert_eq!(ASN1ObjectIdentifier::parse(text), Err(ASN1Error::ObjectIdentifier), "{text}");
    }
}

#[test]
fn universal_elements_take_the_tag_and_form_required_by_x690() {
    let expected = [(ASN1Value::Boolean(true), 1, false), (ASN1Value::Integer(vec![0x01]), 2, false), (ASN1Value::Null, 5, false), (ASN1Value::ObjectIdentifier(ASN1ObjectIdentifier::parse("2.100.3").unwrap()), 6, false), (ASN1Value::Sequence(Vec::new()), 16, true), (ASN1Value::Set(Vec::new()), 17, true)];
    for (value, number, constructed) in expected {
        let element = ASN1Element::universal(value.clone()).unwrap();
        assert_eq!(element.tag, ASN1Tag::new(ASN1Class::Universal, constructed, number), "{value:?}");
        assert_eq!(element.value, value);
    }
    assert_eq!(ASN1Element::universal(ASN1Value::Primitive(Vec::new())), Err(ASN1Error::Tag));
    assert_eq!(ASN1Element::universal(ASN1Value::Constructed(Vec::new())), Err(ASN1Error::Tag));
    assert_eq!(ASN1Tag::universal(ASN1UniversalTag::Sequence, true).universal_tag(), Some(ASN1UniversalTag::Sequence));
    assert_eq!(ASN1Tag::context_specific(16, true).universal_tag(), None);
    assert_eq!(ASN1Tag::context_specific(3, false), ASN1Tag::new(ASN1Class::ContextSpecific, false, 3));
}
