use std::ops::{Add, Sub, Mul, Neg};
use std::fmt;

/// Represents an element in the finite field Z_q
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZqElement {
    value: i32,
    q: i32,
}

impl ZqElement {
    /// Creates a new element in Z_q
    pub fn new(value: i32, q: i32) -> Self {
        let normalized_value = Self::normalize(value, q);
        ZqElement { value: normalized_value, q }
    }

    /// Normalizes a value to be in the range [0, q-1]
    pub fn normalize(value: i32, q: i32) -> i32 {
        let mut result = value % q;
        if result < 0 {
            result += q;
        }
        result
    }

    /// Returns the value in the range [0, q-1]
    pub fn value(&self) -> i32 {
        self.value
    }

    /// Returns the modulus q
    pub fn q(&self) -> i32 {
        self.q
    }

    /// Computes the multiplicative inverse in Z_q
    pub fn inverse(&self) -> Option<Self> {
        if self.value == 0 {
            return None;
        }

        // Extended Euclidean algorithm to find s such that self.value * s ≡ 1 (mod q)
        let mut s = 0;
        let mut old_s = 1;
        let mut r = self.q;
        let mut old_r = self.value;

        while r != 0 {
            let quotient = old_r / r;

            let temp = r;
            r = old_r - quotient * r;
            old_r = temp;

            let temp = s;
            s = old_s - quotient * s;
            old_s = temp;
        }

        if old_r > 1 {
            return None; // Not invertible
        }

        Some(ZqElement::new(old_s, self.q))
    }

    /// Fast Barrett reduction - more efficient for large q values
    pub fn barrett_reduce(x: i32, q: i32, barrett_factor: i64, shift: u32) -> i32 {
        let x_i64 = x as i64;
        // Compute approximate quotient using precomputed factor
        let quotient = ((x_i64 * barrett_factor) >> shift) as i32;
        
        // Compute remainder
        let remainder = x - quotient * q;
        
        // Ensure result in [0, q-1]
        if remainder < 0 || remainder >= q {
            Self::normalize(remainder, q)
        } else {
            remainder
        }
    }

    /// Calculate a precomputed Barrett reduction factor
    pub fn barrett_factor(q: i32, shift: u32) -> i64 {
        // Compute 2^shift / q
        (1i64 << shift) / q as i64
    }
}

impl Add for ZqElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert_eq!(self.q, other.q, "Moduli must be the same");
        ZqElement::new(self.value + other.value, self.q)
    }
}

impl Sub for ZqElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        assert_eq!(self.q, other.q, "Moduli must be the same");
        ZqElement::new(self.value - other.value, self.q)
    }
}

impl Mul for ZqElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        assert_eq!(self.q, other.q, "Moduli must be the same");
        ZqElement::new((self.value as i64 * other.value as i64) as i32, self.q)
    }
}

impl Neg for ZqElement {
    type Output = Self;

    fn neg(self) -> Self {
        ZqElement::new(-self.value, self.q)
    }
}

impl fmt::Display for ZqElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (mod {})", self.value, self.q)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addition() {
        let a = ZqElement::new(5, 13);
        let b = ZqElement::new(10, 13);
        assert_eq!(a + b, ZqElement::new(2, 13));
    }

    #[test]
    fn test_subtraction() {
        let a = ZqElement::new(5, 13);
        let b = ZqElement::new(10, 13);
        assert_eq!(a - b, ZqElement::new(8, 13));
    }

    #[test]
    fn test_multiplication() {
        let a = ZqElement::new(5, 13);
        let b = ZqElement::new(7, 13);
        assert_eq!(a * b, ZqElement::new(9, 13));
    }

    #[test]
    fn test_negation() {
        let a = ZqElement::new(5, 13);
        assert_eq!(-a, ZqElement::new(8, 13));
    }

    #[test]
    fn test_inverse() {
        let a = ZqElement::new(5, 13);
        let inv = a.inverse().unwrap();
        assert_eq!((a * inv).value(), 1);
    }

    #[test]
    fn test_normalize() {
        assert_eq!(ZqElement::normalize(15, 13), 2);
        assert_eq!(ZqElement::normalize(-3, 13), 10);
    }
} 