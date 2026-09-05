use alloc::vec::Vec;

/// The field of two hundred and fifty six elements, over the polynomial that HQC names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GF256 {
    exponents: Vec<u8>,
    logarithms: Vec<u8>,
}

impl GF256 {
    pub const POLYNOMIAL: u16 = 0x11D;
    pub const ORDER: usize = 255;

    pub fn new() -> Self {
        let mut exponents = alloc::vec![0; Self::ORDER * 2];
        let mut logarithms = alloc::vec![0; Self::ORDER + 1];
        let mut value = 1u16;
        for step in 0..Self::ORDER {
            exponents[step] = value as u8;
            exponents[step + Self::ORDER] = value as u8;
            logarithms[value as usize] = step as u8;
            value <<= 1;
            if value & 0x100 != 0 {
                value ^= Self::POLYNOMIAL;
            }
        }
        Self { exponents, logarithms }
    }

    /// The element that the generator raised to `power` gives.
    pub fn power(&self, power: usize) -> u8 {
        self.exponents[power % Self::ORDER]
    }

    pub fn logarithm(&self, value: u8) -> usize {
        self.logarithms[value as usize] as usize
    }

    pub fn multiply(&self, left: u8, right: u8) -> u8 {
        match left == 0 || right == 0 {
            true => 0,
            false => self.exponents[self.logarithms[left as usize] as usize + self.logarithms[right as usize] as usize],
        }
    }

    pub fn inverse(&self, value: u8) -> u8 {
        match value {
            0 => 0,
            value => self.exponents[Self::ORDER - self.logarithms[value as usize] as usize],
        }
    }

    /// The value of a polynomial with ascending coefficients at one point.
    pub fn evaluate(&self, polynomial: &[u8], point: u8) -> u8 {
        let mut total = 0;
        for coefficient in polynomial.iter().rev() {
            total = self.multiply(total, point) ^ coefficient;
        }
        total
    }
}

impl Default for GF256 {
    fn default() -> Self {
        Self::new()
    }
}
