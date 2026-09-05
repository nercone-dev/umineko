use alloc::vec::Vec;
use crate::integer::Integer;

/// A value kept in the Montgomery domain of one [`Modulus`], as fixed length little endian limbs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Residue {
    limbs: Vec<u64>,
}

impl Residue {
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|limb| *limb == 0)
    }
}

/// An odd modulus with the constants that Montgomery multiplication needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modulus {
    modulus: Integer,
    limbs: usize,
    factor: u64,
    converter: Vec<u64>,
}

impl Modulus {
    /// The context of an odd modulus above one, or `None` for anything else.
    pub fn new(modulus: &Integer) -> Option<Self> {
        if modulus.negative() || modulus.is_even() || modulus.bits() < 2 {
            return None;
        }
        let limbs = modulus.limbs().len();
        let mut factor = 1u64;
        for _ in 0..6 {
            factor = factor.wrapping_mul(2u64.wrapping_sub(modulus.limbs()[0].wrapping_mul(factor)));
        }
        let radix = Integer::one().shift_left(limbs * Integer::LIMB_BITS).remainder(modulus)?;
        let converter = Self::widen(&radix.multiply(&radix).remainder(modulus)?, limbs);
        Some(Self { modulus: modulus.clone(), limbs, factor: factor.wrapping_neg(), converter })
    }

    pub fn modulus(&self) -> &Integer {
        &self.modulus
    }

    pub fn limbs(&self) -> usize {
        self.limbs
    }

    pub fn size(&self) -> usize {
        self.modulus.bits().div_ceil(8)
    }

    pub fn widen(value: &Integer, limbs: usize) -> Vec<u64> {
        let mut widened = value.limbs().to_vec();
        widened.resize(limbs, 0);
        widened
    }

    pub fn zero(&self) -> Residue {
        Residue { limbs: alloc::vec![0; self.limbs] }
    }

    pub fn one(&self) -> Residue {
        self.residue(&Integer::one())
    }

    /// The Montgomery form of `value`, reduced first.
    pub fn residue(&self, value: &Integer) -> Residue {
        let reduced = value.modulo(&self.modulus).unwrap_or_else(Integer::zero);
        Residue { limbs: self.montgomery(&Self::widen(&reduced, self.limbs), &self.converter) }
    }

    /// The plain value behind a Montgomery form residue.
    pub fn integer(&self, value: &Residue) -> Integer {
        let mut one = alloc::vec![0; self.limbs];
        one[0] = 1;
        Integer::from_limbs(self.montgomery(&value.limbs, &one), false)
    }

    pub fn add(&self, left: &Residue, right: &Residue) -> Residue {
        let mut limbs = Vec::with_capacity(self.limbs + 1);
        let mut carry = 0u128;
        for index in 0..self.limbs {
            let sum = left.limbs[index] as u128 + right.limbs[index] as u128 + carry;
            limbs.push(sum as u64);
            carry = sum >> Integer::LIMB_BITS;
        }
        limbs.push(carry as u64);
        Residue { limbs: self.settle(limbs) }
    }

    pub fn subtract(&self, left: &Residue, right: &Residue) -> Residue {
        let mut limbs = Vec::with_capacity(self.limbs);
        let mut borrow = 0i128;
        for index in 0..self.limbs {
            let difference = left.limbs[index] as i128 - right.limbs[index] as i128 - borrow;
            limbs.push(difference as u64);
            borrow = (difference < 0) as i128;
        }
        let mask = (borrow as u64).wrapping_neg();
        let mut carry = 0u128;
        for (limb, taken) in limbs.iter_mut().zip(self.modulus.limbs()) {
            let sum = *limb as u128 + (taken & mask) as u128 + carry;
            *limb = sum as u64;
            carry = sum >> Integer::LIMB_BITS;
        }
        Residue { limbs }
    }

    pub fn negate(&self, value: &Residue) -> Residue {
        self.subtract(&self.zero(), value)
    }

    pub fn double(&self, value: &Residue) -> Residue {
        self.add(value, value)
    }

    pub fn multiply(&self, left: &Residue, right: &Residue) -> Residue {
        Residue { limbs: self.montgomery(&left.limbs, &right.limbs) }
    }

    pub fn square(&self, value: &Residue) -> Residue {
        self.multiply(value, value)
    }

    /// `base` raised to `exponent`, over the bits of the exponent from the top, without branching on them.
    pub fn power(&self, base: &Residue, exponent: &Integer) -> Residue {
        let (mut left, mut right) = (self.one(), base.clone());
        for index in (0..exponent.bits()).rev() {
            let bit = exponent.bit(index);
            self.swap(bit, &mut left, &mut right);
            right = self.multiply(&left, &right);
            left = self.square(&left);
            self.swap(bit, &mut left, &mut right);
        }
        left
    }

    pub fn inverse(&self, value: &Residue) -> Option<Residue> {
        let (divisor, coefficient, _) = self.integer(value).extended_gcd(&self.modulus);
        match divisor.value() == Some(1) {
            true => Some(self.residue(&coefficient)),
            false => None,
        }
    }

    /// One of the two square roots of `value`, by the Tonelli-Shanks method over a prime modulus.
    pub fn square_root(&self, value: &Residue) -> Option<Residue> {
        if value.is_zero() {
            return Some(self.zero());
        }
        let one = self.one();
        let order = self.modulus.subtract(&Integer::one());
        if self.power(value, &order.shift_right(1)) != one {
            return None;
        }
        let mut levels = 0;
        while !order.bit(levels) {
            levels += 1;
        }
        let odd = order.shift_right(levels);
        let mut witness = Integer::from_u64(2);
        while self.power(&self.residue(&witness), &order.shift_right(1)) == one {
            witness = witness.add(&Integer::one());
        }
        let mut generator = self.power(&self.residue(&witness), &odd);
        let mut remainder = self.power(value, &odd);
        let mut root = self.power(value, &odd.add(&Integer::one()).shift_right(1));
        while remainder != one {
            let mut depth = 0;
            let mut square = remainder.clone();
            while square != one {
                square = self.square(&square);
                depth += 1;
                if depth == levels {
                    return None;
                }
            }
            let mut shift = generator.clone();
            for _ in 0..levels - depth - 1 {
                shift = self.square(&shift);
            }
            generator = self.square(&shift);
            remainder = self.multiply(&remainder, &generator);
            root = self.multiply(&root, &shift);
            levels = depth;
        }
        Some(root)
    }

    /// `base` raised to `exponent`, entering and leaving the Montgomery domain around the exponentiation.
    pub fn exponentiate(&self, base: &Integer, exponent: &Integer) -> Integer {
        self.integer(&self.power(&self.residue(base), exponent))
    }

    pub fn select(&self, condition: bool, left: &Residue, right: &Residue) -> Residue {
        let mask = (condition as u64).wrapping_neg();
        Residue { limbs: (0..self.limbs).map(|index| (left.limbs[index] & mask) | (right.limbs[index] & !mask)).collect() }
    }

    pub fn swap(&self, condition: bool, left: &mut Residue, right: &mut Residue) {
        let mask = (condition as u64).wrapping_neg();
        for index in 0..self.limbs {
            let difference = (left.limbs[index] ^ right.limbs[index]) & mask;
            left.limbs[index] ^= difference;
            right.limbs[index] ^= difference;
        }
    }

    /// The Montgomery product of two forms, by the coarsely integrated operand scanning method.
    pub fn montgomery(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        let (count, modulus) = (self.limbs, self.modulus.limbs());
        let mut product = alloc::vec![0u64; count + 2];
        for factor in right.iter().take(count) {
            let mut carry = 0u128;
            for offset in 0..count {
                let sum = product[offset] as u128 + left[offset] as u128 * *factor as u128 + carry;
                product[offset] = sum as u64;
                carry = sum >> Integer::LIMB_BITS;
            }
            let sum = product[count] as u128 + carry;
            product[count] = sum as u64;
            product[count + 1] = (sum >> Integer::LIMB_BITS) as u64;
            let factor = product[0].wrapping_mul(self.factor);
            let mut carry = (product[0] as u128 + factor as u128 * modulus[0] as u128) >> Integer::LIMB_BITS;
            for offset in 1..count {
                let sum = product[offset] as u128 + factor as u128 * modulus[offset] as u128 + carry;
                product[offset - 1] = sum as u64;
                carry = sum >> Integer::LIMB_BITS;
            }
            let sum = product[count] as u128 + carry;
            product[count - 1] = sum as u64;
            product[count] = product[count + 1] + (sum >> Integer::LIMB_BITS) as u64;
        }
        product.truncate(count + 1);
        self.settle(product)
    }

    /// One conditional subtraction of the modulus, which brings a value below the modulus.
    pub fn settle(&self, value: Vec<u64>) -> Vec<u64> {
        let mut value = value;
        let mut difference = Vec::with_capacity(value.len());
        let mut borrow = 0i128;
        for (index, limb) in value.iter().enumerate() {
            let taken = self.modulus.limbs().get(index).copied().unwrap_or(0);
            let step = *limb as i128 - taken as i128 - borrow;
            difference.push(step as u64);
            borrow = (step < 0) as i128;
        }
        let mask = (borrow as u64).wrapping_sub(1);
        for (limb, taken) in value.iter_mut().zip(&difference).take(self.limbs) {
            *limb = (taken & mask) | (*limb & !mask);
        }
        value.truncate(self.limbs);
        value
    }
}
