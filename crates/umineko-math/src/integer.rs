use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

/// An arbitrary precision integer, kept as a sign and little endian limbs without trailing zeroes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Integer {
    negative: bool,
    limbs: Vec<u64>,
}

impl Integer {
    pub const LIMB_BITS: usize = 64;
    pub const LIMB_BYTES: usize = 8;

    pub fn zero() -> Self {
        Self { negative: false, limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Self::from_u64(1)
    }

    pub fn from_u64(value: u64) -> Self {
        match value {
            0 => Self::zero(),
            value => Self { negative: false, limbs: alloc::vec![value] },
        }
    }

    pub fn from_limbs(limbs: Vec<u64>, negative: bool) -> Self {
        let mut integer = Self { negative, limbs };
        integer.trim();
        integer
    }

    /// The unsigned value of `data`, read as big endian bytes.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity(data.len().div_ceil(Self::LIMB_BYTES));
        let mut chunks = data.rchunks(Self::LIMB_BYTES);
        for chunk in &mut chunks {
            let mut limb = [0; Self::LIMB_BYTES];
            limb[Self::LIMB_BYTES - chunk.len()..].copy_from_slice(chunk);
            limbs.push(u64::from_be_bytes(limb));
        }
        Self::from_limbs(limbs, false)
    }

    pub fn from_hex(text: &str) -> Option<Self> {
        let mut limbs = Vec::with_capacity(text.len().div_ceil(16));
        let bytes = text.as_bytes();
        let mut chunks = bytes.rchunks(16);
        for chunk in &mut chunks {
            let mut limb = 0u64;
            for digit in chunk {
                limb = (limb << 4) | (digit.to_ascii_lowercase() as char).to_digit(16)? as u64;
            }
            limbs.push(limb);
        }
        Some(Self::from_limbs(limbs, false))
    }

    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    pub fn negative(&self) -> bool {
        self.negative
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|limb| limb & 1 == 1)
    }

    pub fn is_even(&self) -> bool {
        !self.is_odd()
    }

    pub fn bits(&self) -> usize {
        match self.limbs.last() {
            Some(limb) => self.limbs.len() * Self::LIMB_BITS - limb.leading_zeros() as usize,
            None => 0,
        }
    }

    pub fn bit(&self, index: usize) -> bool {
        match self.limbs.get(index / Self::LIMB_BITS) {
            Some(limb) => (limb >> (index % Self::LIMB_BITS)) & 1 == 1,
            None => false,
        }
    }

    pub fn value(&self) -> Option<u64> {
        match self.limbs.len() {
            0 => Some(0),
            1 => Some(self.limbs[0]),
            _ => None,
        }
    }

    /// The magnitude as big endian bytes, without leading zeroes.
    pub fn bytes(&self) -> Vec<u8> {
        let length = self.bits().div_ceil(8);
        self.to_bytes(length)
    }

    /// The magnitude as `length` big endian bytes, padded or truncated on the left.
    pub fn to_bytes(&self, length: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![0; length];
        for (index, byte) in bytes.iter_mut().rev().enumerate() {
            *byte = match self.limbs.get(index / Self::LIMB_BYTES) {
                Some(limb) => (limb >> ((index % Self::LIMB_BYTES) * 8)) as u8,
                None => 0,
            };
        }
        bytes
    }

    pub fn set_bit(&mut self, index: usize) {
        let limb = index / Self::LIMB_BITS;
        if self.limbs.len() <= limb {
            self.limbs.resize(limb + 1, 0);
        }
        self.limbs[limb] |= 1 << (index % Self::LIMB_BITS);
    }

    pub fn negate(&self) -> Self {
        Self::from_limbs(self.limbs.clone(), !self.negative)
    }

    pub fn absolute(&self) -> Self {
        Self::from_limbs(self.limbs.clone(), false)
    }

    pub fn compare(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => Self::compare_limbs(&self.limbs, &other.limbs),
            (true, true) => Self::compare_limbs(&other.limbs, &self.limbs),
        }
    }

    pub fn compare_limbs(left: &[u64], right: &[u64]) -> Ordering {
        match left.len().cmp(&right.len()) {
            Ordering::Equal => left.iter().rev().cmp(right.iter().rev()),
            order => order,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        match self.negative == other.negative {
            true => Self::from_limbs(Self::add_limbs(&self.limbs, &other.limbs), self.negative),
            false => match Self::compare_limbs(&self.limbs, &other.limbs) {
                Ordering::Less => Self::from_limbs(Self::subtract_limbs(&other.limbs, &self.limbs), other.negative),
                _ => Self::from_limbs(Self::subtract_limbs(&self.limbs, &other.limbs), self.negative),
            },
        }
    }

    pub fn subtract(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    pub fn multiply(&self, other: &Self) -> Self {
        Self::from_limbs(Self::multiply_limbs(&self.limbs, &other.limbs), self.negative != other.negative)
    }

    /// The quotient and the remainder, with the quotient truncated towards zero.
    pub fn divide(&self, other: &Self) -> Option<(Self, Self)> {
        let (quotient, remainder) = Self::divide_limbs(&self.limbs, &other.limbs)?;
        Some((Self::from_limbs(quotient, self.negative != other.negative), Self::from_limbs(remainder, self.negative)))
    }

    pub fn remainder(&self, other: &Self) -> Option<Self> {
        self.divide(other).map(|(_, remainder)| remainder)
    }

    /// The remainder with the sign of `other`, so that a positive modulus gives a value in `0..other`.
    pub fn modulo(&self, other: &Self) -> Option<Self> {
        let remainder = self.remainder(other)?;
        match remainder.is_zero() || remainder.negative == other.negative {
            true => Some(remainder),
            false => Some(remainder.add(other)),
        }
    }

    pub fn shift_left(&self, bits: usize) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        let (whole, part) = (bits / Self::LIMB_BITS, bits % Self::LIMB_BITS);
        let mut limbs = alloc::vec![0; whole];
        let mut carry = 0;
        for limb in &self.limbs {
            limbs.push((limb << part) | carry);
            carry = match part {
                0 => 0,
                part => limb >> (Self::LIMB_BITS - part),
            };
        }
        limbs.push(carry);
        Self::from_limbs(limbs, self.negative)
    }

    pub fn shift_right(&self, bits: usize) -> Self {
        let (whole, part) = (bits / Self::LIMB_BITS, bits % Self::LIMB_BITS);
        if whole >= self.limbs.len() {
            return Self::zero();
        }
        let source = &self.limbs[whole..];
        let mut limbs = Vec::with_capacity(source.len());
        for (index, limb) in source.iter().enumerate() {
            let high = match part {
                0 => 0,
                part => source.get(index + 1).map_or(0, |limb| limb << (Self::LIMB_BITS - part)),
            };
            limbs.push((limb >> part) | high);
        }
        Self::from_limbs(limbs, self.negative)
    }

    pub fn gcd(&self, other: &Self) -> Self {
        let (mut left, mut right) = (self.absolute(), other.absolute());
        while !right.is_zero() {
            let remainder = left.remainder(&right).unwrap_or_else(Self::zero);
            left = core::mem::replace(&mut right, remainder.absolute());
        }
        left
    }

    /// The greatest common divisor together with the coefficients that reach it from `self` and `other`.
    pub fn extended_gcd(&self, other: &Self) -> (Self, Self, Self) {
        let (mut old, mut current) = (self.clone(), other.clone());
        let (mut old_left, mut left) = (Self::one(), Self::zero());
        let (mut old_right, mut right) = (Self::zero(), Self::one());
        while !current.is_zero() {
            let (quotient, remainder) = old.divide(&current).unwrap_or((Self::zero(), Self::zero()));
            old = core::mem::replace(&mut current, remainder);
            let (next_left, next_right) = (old_left.subtract(&quotient.multiply(&left)), old_right.subtract(&quotient.multiply(&right)));
            old_left = core::mem::replace(&mut left, next_left);
            old_right = core::mem::replace(&mut right, next_right);
        }
        (old, old_left, old_right)
    }

    pub fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        self.negative = self.negative && !self.limbs.is_empty();
    }

    pub fn add_limbs(left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut limbs = Vec::with_capacity(left.len().max(right.len()) + 1);
        let mut carry = 0u128;
        for index in 0..left.len().max(right.len()) {
            let sum = carry + *left.get(index).unwrap_or(&0) as u128 + *right.get(index).unwrap_or(&0) as u128;
            limbs.push(sum as u64);
            carry = sum >> Self::LIMB_BITS;
        }
        limbs.push(carry as u64);
        limbs
    }

    /// The difference of two magnitudes, where `left` is at least `right`.
    pub fn subtract_limbs(left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut limbs = Vec::with_capacity(left.len());
        let mut borrow = 0i128;
        for index in 0..left.len() {
            let difference = *left.get(index).unwrap_or(&0) as i128 - *right.get(index).unwrap_or(&0) as i128 - borrow;
            limbs.push(difference as u64);
            borrow = (difference < 0) as i128;
        }
        limbs
    }

    pub fn multiply_limbs(left: &[u64], right: &[u64]) -> Vec<u64> {
        if left.is_empty() || right.is_empty() {
            return Vec::new();
        }
        let mut limbs = alloc::vec![0u64; left.len() + right.len()];
        for (index, factor) in right.iter().enumerate() {
            let mut carry = 0u128;
            for (offset, value) in left.iter().enumerate() {
                let product = *value as u128 * *factor as u128 + limbs[index + offset] as u128 + carry;
                limbs[index + offset] = product as u64;
                carry = product >> Self::LIMB_BITS;
            }
            limbs[index + left.len()] = carry as u64;
        }
        limbs
    }

    /// The quotient and the remainder of two magnitudes, by Knuth's algorithm D.
    pub fn divide_limbs(left: &[u64], right: &[u64]) -> Option<(Vec<u64>, Vec<u64>)> {
        let divisor = &right[..=right.iter().rposition(|limb| *limb != 0)?];
        let left = match left.iter().rposition(|limb| *limb != 0) {
            Some(position) => &left[..=position],
            None => &left[..0],
        };
        if Self::compare_limbs(left, divisor) == Ordering::Less {
            return Some((Vec::new(), left.to_vec()));
        }
        if divisor.len() == 1 {
            let (mut quotient, mut remainder) = (alloc::vec![0; left.len()], 0u128);
            for index in (0..left.len()).rev() {
                let value = (remainder << Self::LIMB_BITS) | left[index] as u128;
                quotient[index] = (value / divisor[0] as u128) as u64;
                remainder = value % divisor[0] as u128;
            }
            return Some((quotient, alloc::vec![remainder as u64]));
        }
        let shift = divisor[divisor.len() - 1].leading_zeros() as usize;
        let divisor = Self::from_limbs(divisor.to_vec(), false).shift_left(shift).limbs;
        let mut dividend = Self::from_limbs(left.to_vec(), false).shift_left(shift).limbs;
        let (count, length) = (divisor.len(), left.len() + 1);
        dividend.resize(length, 0);
        let mut quotient = alloc::vec![0; length - count];
        for index in (0..length - count).rev() {
            let numerator = ((dividend[index + count] as u128) << Self::LIMB_BITS) | dividend[index + count - 1] as u128;
            let mut estimate = numerator / divisor[count - 1] as u128;
            let mut rest = numerator % divisor[count - 1] as u128;
            while estimate >> Self::LIMB_BITS != 0 || estimate * divisor[count - 2] as u128 > (rest << Self::LIMB_BITS) + dividend[index + count - 2] as u128 {
                estimate -= 1;
                rest += divisor[count - 1] as u128;
                if rest >> Self::LIMB_BITS != 0 {
                    break;
                }
            }
            let (mut carry, mut borrow) = (0u128, 0i128);
            for offset in 0..count {
                let product = estimate * divisor[offset] as u128 + carry;
                carry = product >> Self::LIMB_BITS;
                let difference = dividend[index + offset] as i128 - (product as u64) as i128 - borrow;
                dividend[index + offset] = difference as u64;
                borrow = (difference < 0) as i128;
            }
            let difference = dividend[index + count] as i128 - carry as i128 - borrow;
            dividend[index + count] = difference as u64;
            if difference < 0 {
                estimate -= 1;
                let mut carry = 0u128;
                for offset in 0..count {
                    let sum = dividend[index + offset] as u128 + divisor[offset] as u128 + carry;
                    dividend[index + offset] = sum as u64;
                    carry = sum >> Self::LIMB_BITS;
                }
                dividend[index + count] = (dividend[index + count] as u128 + carry) as u64;
            }
            quotient[index] = estimate as u64;
        }
        dividend.truncate(count);
        Some((quotient, Self::from_limbs(dividend, false).shift_right(shift).limbs))
    }
}

impl PartialOrd for Integer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Integer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        match self.limbs.last() {
            None => f.write_str("0x0"),
            Some(limb) => {
                write!(f, "0x{limb:x}")?;
                for limb in self.limbs.iter().rev().skip(1) {
                    write!(f, "{limb:016x}")?;
                }
                Ok(())
            }
        }
    }
}
