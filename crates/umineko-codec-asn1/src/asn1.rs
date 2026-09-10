use alloc::{string::String, vec::Vec};
use core::fmt;
use crate::errors::ASN1Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ASN1Encoding {
    BER,
    CER,
    DER,
}

impl ASN1Encoding {
    pub const ALL: [Self; 3] = [Self::BER, Self::CER, Self::DER];

    pub fn canonical(&self) -> bool {
        matches!(self, Self::CER | Self::DER)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BER => "BER",
            Self::CER => "CER",
            Self::DER => "DER",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|encoding| encoding.as_str() == name)
    }
}

impl fmt::Display for ASN1Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ASN1Class {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl ASN1Class {
    pub const ALL: [Self; 4] = [Self::Universal, Self::Application, Self::ContextSpecific, Self::Private];

    pub fn number(&self) -> u8 {
        match self {
            Self::Universal => 0,
            Self::Application => 1,
            Self::ContextSpecific => 2,
            Self::Private => 3,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|class| class.number() == number)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Universal => "Universal",
            Self::Application => "Application",
            Self::ContextSpecific => "Context-specific",
            Self::Private => "Private",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|class| class.as_str() == name)
    }
}

impl fmt::Display for ASN1Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ASN1UniversalTag {
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifier,
    ObjectDescriptor,
    External,
    Real,
    Enumerated,
    EmbeddedPDV,
    UTF8String,
    RelativeOID,
    Time,
    Sequence,
    Set,
    NumericString,
    PrintableString,
    TeletexString,
    VideotexString,
    IA5String,
    UTCTime,
    GeneralizedTime,
    GraphicString,
    VisibleString,
    GeneralString,
    UniversalString,
    CharacterString,
    BMPString,
    Date,
    TimeOfDay,
    DateTime,
    Duration,
    OIDIRI,
    RelativeOIDIRI,
}

impl ASN1UniversalTag {
    pub const ALL: [Self; 35] = [Self::Boolean, Self::Integer, Self::BitString, Self::OctetString, Self::Null, Self::ObjectIdentifier, Self::ObjectDescriptor, Self::External, Self::Real, Self::Enumerated, Self::EmbeddedPDV, Self::UTF8String, Self::RelativeOID, Self::Time, Self::Sequence, Self::Set, Self::NumericString, Self::PrintableString, Self::TeletexString, Self::VideotexString, Self::IA5String, Self::UTCTime, Self::GeneralizedTime, Self::GraphicString, Self::VisibleString, Self::GeneralString, Self::UniversalString, Self::CharacterString, Self::BMPString, Self::Date, Self::TimeOfDay, Self::DateTime, Self::Duration, Self::OIDIRI, Self::RelativeOIDIRI];

    pub fn number(&self) -> u32 {
        match self {
            Self::Boolean => 1,
            Self::Integer => 2,
            Self::BitString => 3,
            Self::OctetString => 4,
            Self::Null => 5,
            Self::ObjectIdentifier => 6,
            Self::ObjectDescriptor => 7,
            Self::External => 8,
            Self::Real => 9,
            Self::Enumerated => 10,
            Self::EmbeddedPDV => 11,
            Self::UTF8String => 12,
            Self::RelativeOID => 13,
            Self::Time => 14,
            Self::Sequence => 16,
            Self::Set => 17,
            Self::NumericString => 18,
            Self::PrintableString => 19,
            Self::TeletexString => 20,
            Self::VideotexString => 21,
            Self::IA5String => 22,
            Self::UTCTime => 23,
            Self::GeneralizedTime => 24,
            Self::GraphicString => 25,
            Self::VisibleString => 26,
            Self::GeneralString => 27,
            Self::UniversalString => 28,
            Self::CharacterString => 29,
            Self::BMPString => 30,
            Self::Date => 31,
            Self::TimeOfDay => 32,
            Self::DateTime => 33,
            Self::Duration => 34,
            Self::OIDIRI => 35,
            Self::RelativeOIDIRI => 36,
        }
    }

    pub fn from_number(number: u32) -> Option<Self> {
        Self::ALL.iter().copied().find(|tag| tag.number() == number)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Boolean => "BOOLEAN",
            Self::Integer => "INTEGER",
            Self::BitString => "BIT STRING",
            Self::OctetString => "OCTET STRING",
            Self::Null => "NULL",
            Self::ObjectIdentifier => "OBJECT IDENTIFIER",
            Self::ObjectDescriptor => "ObjectDescriptor",
            Self::External => "EXTERNAL",
            Self::Real => "REAL",
            Self::Enumerated => "ENUMERATED",
            Self::EmbeddedPDV => "EMBEDDED PDV",
            Self::UTF8String => "UTF8String",
            Self::RelativeOID => "RELATIVE-OID",
            Self::Time => "TIME",
            Self::Sequence => "SEQUENCE",
            Self::Set => "SET",
            Self::NumericString => "NumericString",
            Self::PrintableString => "PrintableString",
            Self::TeletexString => "TeletexString",
            Self::VideotexString => "VideotexString",
            Self::IA5String => "IA5String",
            Self::UTCTime => "UTCTime",
            Self::GeneralizedTime => "GeneralizedTime",
            Self::GraphicString => "GraphicString",
            Self::VisibleString => "VisibleString",
            Self::GeneralString => "GeneralString",
            Self::UniversalString => "UniversalString",
            Self::CharacterString => "CHARACTER STRING",
            Self::BMPString => "BMPString",
            Self::Date => "DATE",
            Self::TimeOfDay => "TIME-OF-DAY",
            Self::DateTime => "DATE-TIME",
            Self::Duration => "DURATION",
            Self::OIDIRI => "OID-IRI",
            Self::RelativeOIDIRI => "RELATIVE-OID-IRI",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|tag| tag.as_str() == name)
    }
}

impl fmt::Display for ASN1UniversalTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ASN1Tag {
    pub class: ASN1Class,
    pub constructed: bool,
    pub number: u32,
}

impl ASN1Tag {
    pub fn new(class: ASN1Class, constructed: bool, number: u32) -> Self {
        Self { class, constructed, number }
    }

    pub fn universal(tag: ASN1UniversalTag, constructed: bool) -> Self {
        Self::new(ASN1Class::Universal, constructed, tag.number())
    }

    pub fn context_specific(number: u32, constructed: bool) -> Self {
        Self::new(ASN1Class::ContextSpecific, constructed, number)
    }

    pub fn universal_tag(&self) -> Option<ASN1UniversalTag> {
        match self.class {
            ASN1Class::Universal => ASN1UniversalTag::from_number(self.number),
            ASN1Class::Application | ASN1Class::ContextSpecific | ASN1Class::Private => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), ASN1Error> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ASN1ObjectIdentifier {
    arcs: Vec<u64>,
}

impl ASN1ObjectIdentifier {
    pub const SEPARATOR: char = '.';

    pub fn new(arcs: &[u64]) -> Result<Self, ASN1Error> {
        match arcs {
            [first, second, ..] if *first < 2 && *second < 40 => Ok(Self { arcs: arcs.to_vec() }),
            [2, second, ..] if *second <= u64::MAX - 80 => Ok(Self { arcs: arcs.to_vec() }),
            _ => Err(ASN1Error::ObjectIdentifier),
        }
    }

    pub fn parse(text: &str) -> Result<Self, ASN1Error> {
        let mut arcs = Vec::new();
        for arc in text.split(Self::SEPARATOR) {
            if arc.is_empty() || !arc.bytes().all(|byte| byte.is_ascii_digit()) || (arc.len() > 1 && arc.starts_with('0')) {
                return Err(ASN1Error::ObjectIdentifier);
            }
            arcs.push(arc.parse().map_err(|_| ASN1Error::ObjectIdentifier)?);
        }
        Self::new(&arcs)
    }

    pub fn arcs(&self) -> &[u64] {
        &self.arcs
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, ASN1Error> {
        todo!()
    }
}

impl fmt::Display for ASN1ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, arc) in self.arcs.iter().enumerate() {
            if index > 0 {
                write!(f, "{}", Self::SEPARATOR)?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ASN1Value {
    Boolean(bool),
    Integer(Vec<u8>),
    BitString { unused: u8, data: Vec<u8> },
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(ASN1ObjectIdentifier),
    Enumerated(Vec<u8>),
    UTF8String(String),
    PrintableString(String),
    IA5String(String),
    VisibleString(String),
    GeneralString(String),
    BMPString(Vec<u16>),
    UTCTime(String),
    GeneralizedTime(String),
    Sequence(Vec<ASN1Element>),
    Set(Vec<ASN1Element>),
    Constructed(Vec<ASN1Element>),
    Primitive(Vec<u8>),
}

impl ASN1Value {
    pub fn universal_tag(&self) -> Option<ASN1UniversalTag> {
        match self {
            Self::Boolean(_) => Some(ASN1UniversalTag::Boolean),
            Self::Integer(_) => Some(ASN1UniversalTag::Integer),
            Self::BitString { .. } => Some(ASN1UniversalTag::BitString),
            Self::OctetString(_) => Some(ASN1UniversalTag::OctetString),
            Self::Null => Some(ASN1UniversalTag::Null),
            Self::ObjectIdentifier(_) => Some(ASN1UniversalTag::ObjectIdentifier),
            Self::Enumerated(_) => Some(ASN1UniversalTag::Enumerated),
            Self::UTF8String(_) => Some(ASN1UniversalTag::UTF8String),
            Self::PrintableString(_) => Some(ASN1UniversalTag::PrintableString),
            Self::IA5String(_) => Some(ASN1UniversalTag::IA5String),
            Self::VisibleString(_) => Some(ASN1UniversalTag::VisibleString),
            Self::GeneralString(_) => Some(ASN1UniversalTag::GeneralString),
            Self::BMPString(_) => Some(ASN1UniversalTag::BMPString),
            Self::UTCTime(_) => Some(ASN1UniversalTag::UTCTime),
            Self::GeneralizedTime(_) => Some(ASN1UniversalTag::GeneralizedTime),
            Self::Sequence(_) => Some(ASN1UniversalTag::Sequence),
            Self::Set(_) => Some(ASN1UniversalTag::Set),
            Self::Constructed(_) | Self::Primitive(_) => None,
        }
    }

    pub fn constructed(&self) -> bool {
        matches!(self, Self::Sequence(_) | Self::Set(_) | Self::Constructed(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ASN1Element {
    pub tag: ASN1Tag,
    pub value: ASN1Value,
}

impl ASN1Element {
    pub fn new(tag: ASN1Tag, value: ASN1Value) -> Self {
        Self { tag, value }
    }

    pub fn universal(value: ASN1Value) -> Result<Self, ASN1Error> {
        match value.universal_tag() {
            Some(tag) => Ok(Self { tag: ASN1Tag::universal(tag, value.constructed()), value }),
            None => Err(ASN1Error::Tag),
        }
    }

    pub fn encode(&self, encoding: ASN1Encoding) -> Result<Vec<u8>, ASN1Error> {
        todo!()
    }

    pub fn decode(data: &[u8], encoding: ASN1Encoding, limits: &ASN1Limits) -> Result<(Self, usize), ASN1Error> {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ASN1Limits {
    pub depth: usize,
    pub length: usize,
}

impl Default for ASN1Limits {
    fn default() -> Self {
        Self { depth: 64, length: 16 * 1024 * 1024 }
    }
}
