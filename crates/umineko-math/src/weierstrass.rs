use alloc::vec::Vec;
use core::fmt;
use crate::errors::MathError;
use crate::integer::Integer;
use crate::modulus::{Modulus, Residue};

/// A point of a short Weierstrass curve in homogeneous projective coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeierstrassPoint {
    pub x: Residue,
    pub y: Residue,
    pub z: Residue,
}

impl WeierstrassPoint {
    pub fn is_identity(&self) -> bool {
        self.z.is_zero()
    }
}

/// A curve `y^2 = x^3 + ax + b` over a prime field, with the complete formulas of Renes, Costello and Batina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Weierstrass {
    name: &'static str,
    field: Modulus,
    order: Modulus,
    a: Residue,
    b: Residue,
    generator: WeierstrassPoint,
    size: usize,
}

impl Weierstrass {
    pub const NAMES: [&'static str; 4] = ["secp256r1", "secp384r1", "secp521r1", "secp256k1"];

    pub fn secp256r1() -> Self {
        Self::new(
            "secp256r1",
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            32,
        )
    }

    pub fn secp384r1() -> Self {
        Self::new(
            "secp384r1",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            48,
        )
    }

    pub fn secp521r1() -> Self {
        Self::new(
            "secp521r1",
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
            "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
            "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
            66,
        )
    }

    pub fn secp256k1() -> Self {
        Self::new(
            "secp256k1",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            32,
        )
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "secp256r1" => Some(Self::secp256r1()),
            "secp384r1" => Some(Self::secp384r1()),
            "secp521r1" => Some(Self::secp521r1()),
            "secp256k1" => Some(Self::secp256k1()),
            _ => None,
        }
    }

    /// Panics when the parameters are not hexadecimal or the prime is even.
    #[allow(clippy::too_many_arguments)]
    pub fn new(name: &'static str, prime: &str, a: &str, b: &str, order: &str, x: &str, y: &str, size: usize) -> Self {
        let parse = |text: &str| Integer::from_hex(text).expect("the curve parameters are hexadecimal");
        let field = Modulus::new(&parse(prime)).expect("the curve prime is odd");
        let order = Modulus::new(&parse(order)).expect("the curve order is odd");
        let (a, b) = (field.residue(&parse(a)), field.residue(&parse(b)));
        let generator = WeierstrassPoint { x: field.residue(&parse(x)), y: field.residue(&parse(y)), z: field.one() };
        Self { name, field, order, a, b, generator, size }
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

    pub fn generator(&self) -> WeierstrassPoint {
        self.generator.clone()
    }

    pub fn identity(&self) -> WeierstrassPoint {
        WeierstrassPoint { x: self.field.zero(), y: self.field.one(), z: self.field.zero() }
    }

    /// The affine coordinates of a point, or `None` for the identity.
    pub fn affine(&self, point: &WeierstrassPoint) -> Option<(Integer, Integer)> {
        let inverse = self.field.inverse(&point.z)?;
        Some((self.field.integer(&self.field.multiply(&point.x, &inverse)), self.field.integer(&self.field.multiply(&point.y, &inverse))))
    }

    pub fn point(&self, x: &Integer, y: &Integer) -> Result<WeierstrassPoint, MathError> {
        let point = WeierstrassPoint { x: self.field.residue(x), y: self.field.residue(y), z: self.field.one() };
        match self.contains(&point) {
            true => Ok(point),
            false => Err(MathError::Point),
        }
    }

    /// Whether an affine point satisfies the curve equation.
    pub fn contains(&self, point: &WeierstrassPoint) -> bool {
        let left = self.field.square(&point.y);
        let right = self.field.add(&self.field.multiply(&self.field.add(&self.field.square(&point.x), &self.a), &point.x), &self.b);
        point.is_identity() || (point.z == self.field.one() && left == right)
    }

    pub fn add(&self, left: &WeierstrassPoint, right: &WeierstrassPoint) -> WeierstrassPoint {
        let (field, a) = (&self.field, &self.a);
        let b3 = field.add(&field.double(&self.b), &self.b);
        let t0 = field.multiply(&left.x, &right.x);
        let t1 = field.multiply(&left.y, &right.y);
        let t2 = field.multiply(&left.z, &right.z);
        let t3 = field.multiply(&field.add(&left.x, &left.y), &field.add(&right.x, &right.y));
        let t3 = field.subtract(&t3, &field.add(&t0, &t1));
        let t4 = field.multiply(&field.add(&left.x, &left.z), &field.add(&right.x, &right.z));
        let t4 = field.subtract(&t4, &field.add(&t0, &t2));
        let t5 = field.multiply(&field.add(&left.y, &left.z), &field.add(&right.y, &right.z));
        let t5 = field.subtract(&t5, &field.add(&t1, &t2));
        let z = field.add(&field.multiply(a, &t4), &field.multiply(&b3, &t2));
        let x = field.subtract(&t1, &z);
        let z = field.add(&t1, &z);
        let y = field.multiply(&x, &z);
        let t1 = field.add(&field.double(&t0), &t0);
        let t2 = field.multiply(a, &t2);
        let t4 = field.multiply(&b3, &t4);
        let t1 = field.add(&t1, &t2);
        let t2 = field.multiply(a, &field.subtract(&t0, &t2));
        let t4 = field.add(&t4, &t2);
        let y = field.add(&y, &field.multiply(&t1, &t4));
        let x = field.subtract(&field.multiply(&t3, &x), &field.multiply(&t5, &t4));
        let z = field.add(&field.multiply(&t5, &z), &field.multiply(&t3, &t1));
        WeierstrassPoint { x, y, z }
    }

    pub fn double(&self, point: &WeierstrassPoint) -> WeierstrassPoint {
        self.add(point, point)
    }

    pub fn negate(&self, point: &WeierstrassPoint) -> WeierstrassPoint {
        WeierstrassPoint { x: point.x.clone(), y: self.field.negate(&point.y), z: point.z.clone() }
    }

    pub fn choose(&self, condition: bool, left: &WeierstrassPoint, right: &WeierstrassPoint) -> WeierstrassPoint {
        WeierstrassPoint {
            x: self.field.select(condition, &left.x, &right.x),
            y: self.field.select(condition, &left.y, &right.y),
            z: self.field.select(condition, &left.z, &right.z),
        }
    }

    /// The multiple of a point, over every bit of the group order so that the scalar stays hidden.
    pub fn multiply(&self, point: &WeierstrassPoint, scalar: &Integer) -> WeierstrassPoint {
        let mut result = self.identity();
        for index in (0..self.order.modulus().bits()).rev() {
            result = self.double(&result);
            result = self.choose(scalar.bit(index), &self.add(&result, point), &result);
        }
        result
    }

    /// The sum of two multiples, for public values such as a signature check.
    pub fn combine(&self, left: &WeierstrassPoint, left_scalar: &Integer, right: &WeierstrassPoint, right_scalar: &Integer) -> WeierstrassPoint {
        let sum = self.add(left, right);
        let mut result = self.identity();
        for index in (0..left_scalar.bits().max(right_scalar.bits())).rev() {
            result = self.double(&result);
            result = match (left_scalar.bit(index), right_scalar.bit(index)) {
                (true, true) => self.add(&result, &sum),
                (true, false) => self.add(&result, left),
                (false, true) => self.add(&result, right),
                (false, false) => result,
            };
        }
        result
    }

    /// A point in the uncompressed or compressed encoding of SEC 1.
    pub fn encode(&self, point: &WeierstrassPoint, compressed: bool) -> Vec<u8> {
        let Some((x, y)) = self.affine(point) else {
            return alloc::vec![0];
        };
        let mut encoded = Vec::with_capacity(1 + self.size * 2);
        match compressed {
            true => encoded.push(2 | y.bit(0) as u8),
            false => encoded.push(4),
        }
        encoded.extend_from_slice(&x.to_bytes(self.size));
        if !compressed {
            encoded.extend_from_slice(&y.to_bytes(self.size));
        }
        encoded
    }

    pub fn reduced(&self, value: &Integer) -> bool {
        value.compare(self.field.modulus()) == core::cmp::Ordering::Less
    }

    pub fn decode(&self, data: &[u8]) -> Result<WeierstrassPoint, MathError> {
        match data.split_first() {
            Some((0, [])) => Ok(self.identity()),
            Some((4, rest)) if rest.len() == self.size * 2 => {
                let (x, y) = (Integer::from_bytes(&rest[..self.size]), Integer::from_bytes(&rest[self.size..]));
                match self.reduced(&x) && self.reduced(&y) {
                    true => self.point(&x, &y),
                    false => Err(MathError::Point),
                }
            }
            Some((tag @ (2 | 3), rest)) if rest.len() == self.size => {
                let x = Integer::from_bytes(rest);
                if !self.reduced(&x) {
                    return Err(MathError::Point);
                }
                let x = self.field.residue(&x);
                let square = self.field.add(&self.field.multiply(&self.field.add(&self.field.square(&x), &self.a), &x), &self.b);
                let root = self.field.square_root(&square).ok_or(MathError::Point)?;
                let root = self.field.integer(&root);
                let root = match root.bit(0) == (tag & 1 == 1) {
                    true => root,
                    false => self.field.modulus().subtract(&root),
                };
                self.point(&self.field.integer(&x), &root)
            }
            _ => Err(MathError::Encoding),
        }
    }
}

impl fmt::Display for Weierstrass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}
