//! The transforms a prefix coded meta-block reads dictionary words through.

use alloc::vec::Vec;

/// The change a transform makes to the word it carries, between its prefix and its suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrotliChange {
    Identity,
    OmitFirst(u8),
    OmitLast(u8),
    UppercaseFirst,
    UppercaseAll,
}

impl BrotliChange {
    /// The bytes of `word` this change leaves behind, uppercased where it asks for that.
    pub fn apply(&self, word: &[u8]) -> Vec<u8> {
        let mut output = match self {
            Self::OmitFirst(count) => word.get(*count as usize..).unwrap_or_default().to_vec(),
            Self::OmitLast(count) => word.get(..word.len().saturating_sub(*count as usize)).unwrap_or_default().to_vec(),
            _ => word.to_vec(),
        };
        let taken = match self {
            Self::UppercaseFirst => 1,
            Self::UppercaseAll => output.len(),
            _ => 0,
        };
        let mut offset = 0;
        for _ in 0..taken {
            match offset < output.len() {
                true => offset += Self::uppercase(&mut output[offset..]),
                false => break,
            }
        }
        output
    }

    /// Uppercases the first character of `word` and reports the bytes it spans.
    ///
    /// The format names one model of its own for this, which holds for one byte characters and
    /// stands in for the rest; a decoder that follows any other model reads other words.
    pub fn uppercase(word: &mut [u8]) -> usize {
        match word {
            [] => 0,
            [first, ..] if *first < 0xC0 => {
                if first.is_ascii_lowercase() {
                    *first ^= 32;
                }
                1
            }
            [first, second, ..] if *first < 0xE0 => {
                *second ^= 32;
                2
            }
            [_, _, third, ..] => {
                *third ^= 5;
                3
            }
            _ => word.len(),
        }
    }
}

/// One transform of the static dictionary: a prefix, a change to the word, and a suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BrotliTransform {
    pub prefix: usize,
    pub change: BrotliChange,
    pub suffix: usize,
}

impl BrotliTransform {
    /// The prefixes and suffixes every transform is built out of.
    pub const AFFIXES: [&'static [u8]; 50] = [
        b" ",
        b", ",
        b" of the ",
        b" of ",
        b"s ",
        b".",
        b" and ",
        b" in ",
        b"\"",
        b" to ",
        b"\">",
        b"\x0A",
        b". ",
        b"]",
        b" for ",
        b" a ",
        b" that ",
        b"'",
        b" with ",
        b" from ",
        b" by ",
        b"(",
        b". The ",
        b" on ",
        b" as ",
        b" is ",
        b"ing ",
        b"\x0A\x09",
        b":",
        b"ed ",
        b"=\"",
        b" at ",
        b"ly ",
        b",",
        b"='",
        b".com/",
        b". This ",
        b" not ",
        b"er ",
        b"al ",
        b"ful ",
        b"ive ",
        b"less ",
        b"est ",
        b"ize ",
        b"\xC2\xA0",
        b"ous ",
        b" the ",
        b"e ",
        b""
    ];
    /// The transforms RFC 7932 names, in the order a distance picks them out by.
    pub const TRANSFORMS: [BrotliTransform; 121] = [
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 0 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(1), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 47 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 49 },
        BrotliTransform { prefix: 4, change: BrotliChange::Identity, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 3 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 6 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(2), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(1), suffix: 49 },
        BrotliTransform { prefix: 1, change: BrotliChange::Identity, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 1 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 7 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 9 },
        BrotliTransform { prefix: 48, change: BrotliChange::Identity, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 8 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 5 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 10 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 11 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(3), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 13 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 14 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(3), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(2), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 15 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 16 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 12 },
        BrotliTransform { prefix: 5, change: BrotliChange::Identity, suffix: 49 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 1 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(4), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 18 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 17 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 19 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 20 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(5), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(6), suffix: 49 },
        BrotliTransform { prefix: 47, change: BrotliChange::Identity, suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(4), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 22 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 23 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 24 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 25 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(7), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(1), suffix: 26 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 27 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 28 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 12 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 29 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(9), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitFirst(7), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(6), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 21 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 1 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(8), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 31 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 32 },
        BrotliTransform { prefix: 47, change: BrotliChange::Identity, suffix: 3 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(5), suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::OmitLast(9), suffix: 49 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 1 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 8 },
        BrotliTransform { prefix: 5, change: BrotliChange::Identity, suffix: 21 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 10 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 30 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 5 },
        BrotliTransform { prefix: 35, change: BrotliChange::Identity, suffix: 49 },
        BrotliTransform { prefix: 47, change: BrotliChange::Identity, suffix: 2 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 17 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 36 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 33 },
        BrotliTransform { prefix: 5, change: BrotliChange::Identity, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 21 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 5 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 37 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 30 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 38 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseAll, suffix: 0 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 39 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseAll, suffix: 49 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 34 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 8 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 12 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 21 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 40 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 12 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 41 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 42 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 17 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 43 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 5 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 10 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 34 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 33 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 44 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 5 },
        BrotliTransform { prefix: 45, change: BrotliChange::Identity, suffix: 49 },
        BrotliTransform { prefix: 0, change: BrotliChange::Identity, suffix: 33 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 30 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 30 },
        BrotliTransform { prefix: 49, change: BrotliChange::Identity, suffix: 46 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 1 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseFirst, suffix: 34 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 33 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseAll, suffix: 30 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseAll, suffix: 1 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 33 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 21 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 12 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseAll, suffix: 5 },
        BrotliTransform { prefix: 49, change: BrotliChange::UppercaseAll, suffix: 34 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseAll, suffix: 12 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 30 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseAll, suffix: 34 },
        BrotliTransform { prefix: 0, change: BrotliChange::UppercaseFirst, suffix: 34 }
    ];

    /// The transform at `index`, if the format names one there.
    pub fn at(index: usize) -> Option<Self> {
        Self::TRANSFORMS.get(index).copied()
    }

    /// The bytes `word` reads as through this transform.
    pub fn apply(&self, word: &[u8]) -> Vec<u8> {
        let mut output = Self::AFFIXES[self.prefix].to_vec();
        output.extend_from_slice(&self.change.apply(word));
        output.extend_from_slice(Self::AFFIXES[self.suffix]);
        output
    }
}
