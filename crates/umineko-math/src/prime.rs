use crate::integer::Integer;
use crate::modulus::Modulus;

pub struct Prime;

impl Prime {
    pub const ROUNDS: usize = 40;
    /// The primes below three hundred, which trial division and the Miller-Rabin bases share.
    pub const SMALL: [u64; 62] = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
        73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
        179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293,
    ];

    /// Whether one of the small primes divides `candidate`, which is not itself one of them.
    pub fn divisible(candidate: &Integer) -> bool {
        Self::SMALL.iter().any(|prime| {
            let prime = Integer::from_u64(*prime);
            candidate.compare(&prime) != core::cmp::Ordering::Equal && candidate.remainder(&prime).is_some_and(|remainder| remainder.is_zero())
        })
    }

    /// Whether `candidate` passes `rounds` Miller-Rabin tests over the small primes as bases.
    pub fn probable(candidate: &Integer, rounds: usize) -> bool {
        if candidate.negative() || candidate.bits() < 2 {
            return false;
        }
        if Self::SMALL.contains(&candidate.value().unwrap_or(0)) {
            return true;
        }
        candidate.is_odd() && !Self::divisible(candidate) && Self::rabin(candidate, rounds)
    }

    pub fn rabin(candidate: &Integer, rounds: usize) -> bool {
        let Some(modulus) = Modulus::new(candidate) else {
            return false;
        };
        let order = candidate.subtract(&Integer::one());
        let mut levels = 0;
        while !order.bit(levels) {
            levels += 1;
        }
        let odd = order.shift_right(levels);
        let (one, last) = (modulus.one(), modulus.residue(&order));
        for base in Self::SMALL.iter().take(rounds) {
            let base = modulus.residue(&Integer::from_u64(*base));
            if base.is_zero() {
                continue;
            }
            let mut value = modulus.power(&base, &odd);
            if value == one || value == last {
                continue;
            }
            let mut composite = true;
            for _ in 1..levels {
                value = modulus.square(&value);
                if value == last {
                    composite = false;
                    break;
                }
            }
            if composite {
                return false;
            }
        }
        true
    }

    /// A probable prime of exactly `bits` bits, drawn from `random` until one appears.
    pub fn generate(bits: usize, rounds: usize, random: &mut impl FnMut(&mut [u8])) -> Integer {
        let mut bytes = alloc::vec![0; bits.div_ceil(8)];
        loop {
            random(&mut bytes);
            let mut candidate = Integer::from_bytes(&bytes).shift_right(bytes.len() * 8 - bits);
            candidate.set_bit(bits - 1);
            candidate.set_bit(bits - 2);
            candidate.set_bit(0);
            if Self::probable(&candidate, rounds) {
                return candidate;
            }
        }
    }
}
