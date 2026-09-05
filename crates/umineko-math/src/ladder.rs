use alloc::vec::Vec;
use core::fmt;
use crate::errors::MathError;
use crate::integer::Integer;
use crate::modulus::{Modulus, Residue};

/// A Montgomery curve driven by the x coordinate ladder of RFC 7748.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ladder {
    name: &'static str,
    field: Modulus,
    constant: Residue,
    size: usize,
    bits: usize,
    point: u8,
    mask: u8,
    low: u8,
    high: u8,
    set: u8,
}

impl Ladder {
    pub const NAMES: [&'static str; 2] = ["X25519", "X448"];

    pub fn x25519() -> Self {
        Self::new("X25519", "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 121665, 32, 255, 9, 0x7f, 248, 127, 64)
    }

    pub fn x448() -> Self {
        Self::new("X448", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 39081, 56, 448, 5, 0xff, 252, 255, 128)
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "X25519" => Some(Self::x25519()),
            "X448" => Some(Self::x448()),
            _ => None,
        }
    }

    /// Panics when the prime is not hexadecimal or is even.
    #[allow(clippy::too_many_arguments)]
    pub fn new(name: &'static str, prime: &str, constant: u64, size: usize, bits: usize, point: u8, mask: u8, low: u8, high: u8, set: u8) -> Self {
        let field = Modulus::new(&Integer::from_hex(prime).expect("the curve prime is hexadecimal")).expect("the curve prime is odd");
        let constant = field.residue(&Integer::from_u64(constant));
        Self { name, field, constant, size, bits, point, mask, low, high, set }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn field(&self) -> &Modulus {
        &self.field
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    /// The x coordinate of the standard base point, in the little endian encoding of RFC 7748.
    pub fn base(&self) -> Vec<u8> {
        let mut base = alloc::vec![0; self.size];
        base[0] = self.point;
        base
    }

    pub fn clamp(&self, scalar: &mut [u8]) {
        if let Some((last, rest)) = scalar.split_last_mut() {
            if let Some(first) = rest.first_mut() {
                *first &= self.low;
            }
            *last &= self.high;
            *last |= self.set;
        }
    }

    pub fn scalar(&self, data: &[u8]) -> Result<Integer, MathError> {
        if data.len() != self.size {
            return Err(MathError::Length);
        }
        let mut bytes = data.to_vec();
        self.clamp(&mut bytes);
        bytes.reverse();
        Ok(Integer::from_bytes(&bytes))
    }

    pub fn coordinate(&self, data: &[u8]) -> Result<Residue, MathError> {
        if data.len() != self.size {
            return Err(MathError::Length);
        }
        let mut bytes = data.to_vec();
        bytes[self.size - 1] &= self.mask;
        bytes.reverse();
        Ok(self.field.residue(&Integer::from_bytes(&bytes)))
    }

    pub fn encode(&self, value: &Residue) -> Vec<u8> {
        let mut encoded = self.field.integer(value).to_bytes(self.size);
        encoded.reverse();
        encoded
    }

    pub fn multiply(&self, scalar: &[u8], point: &[u8]) -> Result<Vec<u8>, MathError> {
        let (scalar, point) = (self.scalar(scalar)?, self.coordinate(point)?);
        Ok(self.encode(&self.ladder(&scalar, &point)))
    }

    pub fn multiply_base(&self, scalar: &[u8]) -> Result<Vec<u8>, MathError> {
        self.multiply(scalar, &self.base())
    }

    /// The x coordinate of the multiple of a point, by the ladder of Montgomery.
    pub fn ladder(&self, scalar: &Integer, point: &Residue) -> Residue {
        let field = &self.field;
        let (mut second, mut second_z) = (field.one(), field.zero());
        let (mut third, mut third_z) = (point.clone(), field.one());
        let mut swap = false;
        for index in (0..self.bits).rev() {
            let bit = scalar.bit(index);
            field.swap(swap != bit, &mut second, &mut third);
            field.swap(swap != bit, &mut second_z, &mut third_z);
            swap = bit;
            let sum = field.add(&second, &second_z);
            let difference = field.subtract(&second, &second_z);
            let square_sum = field.square(&sum);
            let square_difference = field.square(&difference);
            let step = field.subtract(&square_sum, &square_difference);
            let inner = field.multiply(&field.subtract(&third, &third_z), &sum);
            let outer = field.multiply(&field.add(&third, &third_z), &difference);
            third = field.square(&field.add(&inner, &outer));
            third_z = field.multiply(point, &field.square(&field.subtract(&inner, &outer)));
            second = field.multiply(&square_sum, &square_difference);
            second_z = field.multiply(&step, &field.add(&square_sum, &field.multiply(&self.constant, &step)));
        }
        field.swap(swap, &mut second, &mut third);
        field.swap(swap, &mut second_z, &mut third_z);
        match field.inverse(&second_z) {
            Some(inverse) => field.multiply(&second, &inverse),
            None => field.zero(),
        }
    }
}

impl fmt::Display for Ladder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}
