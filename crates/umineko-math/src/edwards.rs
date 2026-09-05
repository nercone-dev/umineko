use alloc::vec::Vec;
use core::fmt;
use crate::errors::MathError;
use crate::integer::Integer;
use crate::modulus::{Modulus, Residue};

/// A point of a twisted Edwards curve in extended coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdwardsPoint {
    pub x: Residue,
    pub y: Residue,
    pub z: Residue,
    pub t: Residue,
}

/// A curve `ax^2 + y^2 = 1 + dx^2y^2` over a prime field, with the unified formulas of Hisil and others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edwards {
    name: &'static str,
    field: Modulus,
    order: Modulus,
    a: Residue,
    d: Residue,
    generator: EdwardsPoint,
    size: usize,
    bits: usize,
    cofactor: usize,
}

impl Edwards {
    pub const NAMES: [&'static str; 2] = ["Ed25519", "Ed448"];

    pub fn ed25519() -> Self {
        Self::new(
            "Ed25519",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec",
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
            "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
            "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
            "6666666666666666666666666666666666666666666666666666666666666658",
            32,
            8,
        )
    }

    pub fn ed448() -> Self {
        Self::new(
            "Ed448",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756",
            "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
            "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e",
            "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
            57,
            4,
        )
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Ed25519" => Some(Self::ed25519()),
            "Ed448" => Some(Self::ed448()),
            _ => None,
        }
    }

    /// Panics when the parameters are not hexadecimal or the prime is even.
    #[allow(clippy::too_many_arguments)]
    pub fn new(name: &'static str, prime: &str, a: &str, d: &str, order: &str, x: &str, y: &str, size: usize, cofactor: usize) -> Self {
        let parse = |text: &str| Integer::from_hex(text).expect("the curve parameters are hexadecimal");
        let field = Modulus::new(&parse(prime)).expect("the curve prime is odd");
        let order = Modulus::new(&parse(order)).expect("the curve order is odd");
        let (a, d) = (field.residue(&parse(a)), field.residue(&parse(d)));
        let (x, y) = (field.residue(&parse(x)), field.residue(&parse(y)));
        let generator = EdwardsPoint { t: field.multiply(&x, &y), x, y, z: field.one() };
        let bits = size * 8;
        Self { name, field, order, a, d, generator, size, bits, cofactor }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn field(&self) -> &Modulus {
        &self.field
    }

    pub fn order(&self) -> &Modulus {
        &self.order
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn cofactor(&self) -> usize {
        self.cofactor
    }

    pub fn generator(&self) -> EdwardsPoint {
        self.generator.clone()
    }

    pub fn identity(&self) -> EdwardsPoint {
        EdwardsPoint { x: self.field.zero(), y: self.field.one(), z: self.field.one(), t: self.field.zero() }
    }

    pub fn affine(&self, point: &EdwardsPoint) -> Option<(Integer, Integer)> {
        let inverse = self.field.inverse(&point.z)?;
        Some((self.field.integer(&self.field.multiply(&point.x, &inverse)), self.field.integer(&self.field.multiply(&point.y, &inverse))))
    }

    pub fn equals(&self, left: &EdwardsPoint, right: &EdwardsPoint) -> bool {
        self.field.multiply(&left.x, &right.z) == self.field.multiply(&right.x, &left.z) && self.field.multiply(&left.y, &right.z) == self.field.multiply(&right.y, &left.z)
    }

    pub fn contains(&self, point: &EdwardsPoint) -> bool {
        let (square_x, square_y, square_z) = (self.field.square(&point.x), self.field.square(&point.y), self.field.square(&point.z));
        let left = self.field.multiply(&self.field.add(&self.field.multiply(&self.a, &square_x), &square_y), &square_z);
        let right = self.field.add(&self.field.square(&square_z), &self.field.multiply(&self.d, &self.field.multiply(&square_x, &square_y)));
        left == right && self.field.multiply(&point.t, &point.z) == self.field.multiply(&point.x, &point.y)
    }

    pub fn add(&self, left: &EdwardsPoint, right: &EdwardsPoint) -> EdwardsPoint {
        let field = &self.field;
        let first = field.multiply(&left.x, &right.x);
        let second = field.multiply(&left.y, &right.y);
        let third = field.multiply(&self.d, &field.multiply(&left.t, &right.t));
        let fourth = field.multiply(&left.z, &right.z);
        let sum = field.subtract(&field.multiply(&field.add(&left.x, &left.y), &field.add(&right.x, &right.y)), &field.add(&first, &second));
        let difference = field.subtract(&fourth, &third);
        let total = field.add(&fourth, &third);
        let rest = field.subtract(&second, &field.multiply(&self.a, &first));
        EdwardsPoint {
            x: field.multiply(&sum, &difference),
            y: field.multiply(&total, &rest),
            t: field.multiply(&sum, &rest),
            z: field.multiply(&difference, &total),
        }
    }

    pub fn double(&self, point: &EdwardsPoint) -> EdwardsPoint {
        self.add(point, point)
    }

    pub fn negate(&self, point: &EdwardsPoint) -> EdwardsPoint {
        EdwardsPoint { x: self.field.negate(&point.x), y: point.y.clone(), z: point.z.clone(), t: self.field.negate(&point.t) }
    }

    pub fn choose(&self, condition: bool, left: &EdwardsPoint, right: &EdwardsPoint) -> EdwardsPoint {
        EdwardsPoint {
            x: self.field.select(condition, &left.x, &right.x),
            y: self.field.select(condition, &left.y, &right.y),
            z: self.field.select(condition, &left.z, &right.z),
            t: self.field.select(condition, &left.t, &right.t),
        }
    }

    /// The multiple of a point, over every bit of the encoding so that the scalar stays hidden.
    pub fn multiply(&self, point: &EdwardsPoint, scalar: &Integer) -> EdwardsPoint {
        let mut result = self.identity();
        for index in (0..self.bits).rev() {
            result = self.double(&result);
            result = self.choose(scalar.bit(index), &self.add(&result, point), &result);
        }
        result
    }

    pub fn multiply_cofactor(&self, point: &EdwardsPoint) -> EdwardsPoint {
        let mut result = point.clone();
        for _ in 0..self.cofactor.trailing_zeros() {
            result = self.double(&result);
        }
        result
    }

    /// A point as the little endian ordinate of RFC 8032, with the sign of the abscissa in the highest bit.
    pub fn encode(&self, point: &EdwardsPoint) -> Vec<u8> {
        let Some((x, y)) = self.affine(point) else {
            return alloc::vec![0; self.size];
        };
        let mut encoded = y.to_bytes(self.size);
        encoded.reverse();
        encoded[self.size - 1] |= (x.bit(0) as u8) << 7;
        encoded
    }

    pub fn decode(&self, data: &[u8]) -> Result<EdwardsPoint, MathError> {
        if data.len() != self.size {
            return Err(MathError::Length);
        }
        let mut bytes = data.to_vec();
        let sign = bytes[self.size - 1] >> 7 == 1;
        bytes[self.size - 1] &= 0x7f;
        bytes.reverse();
        let y = Integer::from_bytes(&bytes);
        if y.compare(self.field.modulus()) != core::cmp::Ordering::Less {
            return Err(MathError::Point);
        }
        let y = self.field.residue(&y);
        let square = self.field.square(&y);
        let numerator = self.field.subtract(&square, &self.field.one());
        let denominator = self.field.subtract(&self.field.multiply(&self.d, &square), &self.a);
        let inverse = self.field.inverse(&denominator).ok_or(MathError::Point)?;
        let root = self.field.square_root(&self.field.multiply(&numerator, &inverse)).ok_or(MathError::Point)?;
        if root.is_zero() && sign {
            return Err(MathError::Point);
        }
        let root = match self.field.integer(&root).bit(0) == sign {
            true => root,
            false => self.field.negate(&root),
        };
        Ok(EdwardsPoint { t: self.field.multiply(&root, &y), x: root, y, z: self.field.one() })
    }
}

impl fmt::Display for Edwards {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}
