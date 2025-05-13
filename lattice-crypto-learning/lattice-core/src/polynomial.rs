use std::ops::{Add, Sub, Neg};
use std::fmt;
use crate::params::PolyModulusInfo;
use crate::zq::ZqElement;

/// Represents a polynomial in the ring R_q = Z_q[X]/(f(X))
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    /// Coefficients of the polynomial
    pub coeffs: Vec<ZqElement>,
    /// Information about the polynomial modulus
    pub modulus_info: PolyModulusInfo,
}

impl Polynomial {
    /// Creates a new polynomial with given coefficients
    pub fn new(coeffs: Vec<ZqElement>, modulus_info: PolyModulusInfo) -> Self {
        let n = modulus_info.degree;
        assert!(coeffs.len() <= n, "Polynomial has too many coefficients");
        
        // If the coefficients vector is smaller than n, pad with zeros
        let mut padded_coeffs = coeffs;
        if padded_coeffs.len() < n {
            let q = modulus_info.q;
            padded_coeffs.resize(n, ZqElement::new(0, q));
        }
        
        Polynomial {
            coeffs: padded_coeffs,
            modulus_info,
        }
    }
    
    /// Creates a new zero polynomial
    pub fn zero(modulus_info: PolyModulusInfo) -> Self {
        let n = modulus_info.degree;
        let q = modulus_info.q;
        let coeffs = vec![ZqElement::new(0, q); n];
        Polynomial::new(coeffs, modulus_info)
    }
    
    /// Creates a polynomial with a single coefficient (constant polynomial)
    pub fn constant(value: i32, modulus_info: PolyModulusInfo) -> Self {
        let mut poly = Self::zero(modulus_info);
        poly.coeffs[0] = ZqElement::new(value, modulus_info.q);
        poly
    }
    
    /// Evaluates the polynomial at a given point x
    pub fn evaluate(&self, x: ZqElement) -> ZqElement {
        let mut result = ZqElement::new(0, self.modulus_info.q);
        let mut power = ZqElement::new(1, self.modulus_info.q);
        
        for coeff in &self.coeffs {
            result = result + (*coeff * power);
            power = power * x;
        }
        
        result
    }
    
    /// Multiplies two polynomials using schoolbook algorithm
    /// Note: This is not NTT-based multiplication, which is more efficient
    pub fn schoolbook_mul(&self, other: &Self) -> Self {
        assert_eq!(self.modulus_info.q, other.modulus_info.q,
                  "Polynomials must have the same coefficient modulus");
        assert_eq!(self.modulus_info.degree, other.modulus_info.degree,
                  "Polynomials must have the same degree");
        
        let n = self.modulus_info.degree;
        let q = self.modulus_info.q;
        let mut result = vec![ZqElement::new(0, q); n];
        
        // Schoolbook multiplication without reduction by f(X) yet
        for i in 0..n {
            for j in 0..n {
                let product = self.coeffs[i] * other.coeffs[j];
                let idx = (i + j) % n;
                result[idx] = result[idx] + product;
                
                // For X^n + 1 reduction, we need to handle the wraparound with negation
                if i + j >= n {
                    result[idx] = result[idx] - product - product;
                }
            }
        }
        
        Polynomial::new(result, self.modulus_info)
    }
    
    /// Multiplies the polynomial by a scalar
    pub fn scalar_mul(&self, scalar: ZqElement) -> Self {
        let mut result = self.clone();
        for i in 0..self.coeffs.len() {
            result.coeffs[i] = self.coeffs[i] * scalar;
        }
        result
    }
    
    /// Converts a polynomial to its byte representation
    pub fn to_bytes(&self, coeff_bits: usize) -> Vec<u8> {
        let n = self.modulus_info.degree;
        let mut bytes = Vec::new();
        let coeff_bytes = (coeff_bits + 7) / 8;
        
        // Reserve space for all coefficients
        bytes.reserve(n * coeff_bytes);
        
        // Fill in bytes with coefficient values
        for coeff in &self.coeffs {
            let mut coeff_val = coeff.value() as u32;
            for _ in 0..coeff_bytes {
                bytes.push((coeff_val & 0xFF) as u8);
                coeff_val >>= 8;
            }
        }
        
        bytes
    }
    
    /// Creates a polynomial from its byte representation
    pub fn from_bytes(bytes: &[u8], modulus_info: PolyModulusInfo, coeff_bits: usize) -> Self {
        let n = modulus_info.degree;
        let q = modulus_info.q;
        let coeff_bytes = (coeff_bits + 7) / 8;
        
        // If not enough bytes, return a zero polynomial
        if bytes.len() < n * coeff_bytes {
            return Polynomial::zero(modulus_info);
        }
        
        let mut coeffs = Vec::with_capacity(n);
        
        // Extract coefficients from bytes
        for i in 0..n {
            let offset = i * coeff_bytes;
            let mut coeff_val = 0i32;
            
            for j in 0..coeff_bytes {
                if offset + j < bytes.len() {
                    coeff_val |= (bytes[offset + j] as i32) << (8 * j);
                }
            }
            
            // Mask to the appropriate number of bits
            let mask = (1 << coeff_bits) - 1;
            coeff_val &= mask;
            
            coeffs.push(ZqElement::new(coeff_val, q));
        }
        
        Polynomial::new(coeffs, modulus_info)
    }
    
    /// Compresses polynomial coefficients from q bits to p bits
    pub fn compress(&self, p: usize) -> Self {
        let q = self.modulus_info.q as i64;
        let mut result = self.clone();
        let mod_size = 1 << p;
        
        for i in 0..self.coeffs.len() {
            let x = self.coeffs[i].value() as i64;
            // Compute (p/q) * x rounded
            let compressed = ((((1 << p) as i64) * x + (q >> 1)) / q) as i32;
            result.coeffs[i] = ZqElement::new(compressed, (1 << p) as i32);
        }
        
        // Update modulus info to reflect the new coefficient range
        result.modulus_info.q = mod_size as i32;
        
        result
    }
    
    /// Decompresses polynomial coefficients from p bits to q bits
    pub fn decompress(&self, q: i32) -> Self {
        // We don't need to compute p as a separate variable
        let p_val = self.modulus_info.q;
        let mut result = self.clone();
        
        for i in 0..self.coeffs.len() {
            let x = self.coeffs[i].value() as i64;
            // Compute (q/p) * x
            let decompressed = ((q as i64 * x + (p_val as i64 >> 1)) / p_val as i64) as i32;
            result.coeffs[i] = ZqElement::new(decompressed, q);
        }
        
        // Update the modulus info
        result.modulus_info.q = q;
        
        result
    }
    
    /// Extracts high bits according to decomposition procedure (HIGHS in paper)
    pub fn high_bits(&self, gamma2: i32) -> Self {
        let q = self.modulus_info.q;
        let mut result = self.clone();
        
        for i in 0..self.coeffs.len() {
            let coeff = self.coeffs[i].value();
            // Extract high bits as per Dilithium approach, not exact formula but conceptually similar
            let high = coeff / gamma2;
            result.coeffs[i] = ZqElement::new(high, q);
        }
        
        result
    }
    
    /// Extracts low bits according to decomposition procedure (LOWS in paper)
    pub fn low_bits(&self, gamma2: i32) -> Self {
        let q = self.modulus_info.q;
        let mut result = self.clone();
        
        for i in 0..self.coeffs.len() {
            let coeff = self.coeffs[i].value();
            // Extract low bits as per Dilithium approach
            let low = coeff % gamma2;
            // Adjust to center around 0
            let low_centered = if low > gamma2 / 2 {
                low - gamma2
            } else {
                low
            };
            result.coeffs[i] = ZqElement::new(low_centered, q);
        }
        
        result
    }
    
    /// Computes infinity norm (maximum absolute value of any coefficient)
    pub fn infinity_norm(&self) -> i32 {
        let mut max_norm = 0;
        let q = self.modulus_info.q;
        let q_half = q / 2;
        
        for coeff in &self.coeffs {
            // Get centered representation
            let val = coeff.value();
            let centered_val = if val > q_half { val - q } else { val };
            
            let abs_val = centered_val.abs();
            if abs_val > max_norm {
                max_norm = abs_val;
            }
        }
        
        max_norm
    }
}

impl Add for Polynomial {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        assert_eq!(self.modulus_info.q, other.modulus_info.q,
                  "Polynomials must have the same coefficient modulus");
        assert_eq!(self.modulus_info.degree, other.modulus_info.degree,
                  "Polynomials must have the same degree");
        
        let mut result = self.clone();
        for i in 0..self.coeffs.len() {
            result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        
        result
    }
}

impl Sub for Polynomial {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        assert_eq!(self.modulus_info.q, other.modulus_info.q,
                  "Polynomials must have the same coefficient modulus");
        assert_eq!(self.modulus_info.degree, other.modulus_info.degree,
                  "Polynomials must have the same degree");
        
        let mut result = self.clone();
        for i in 0..self.coeffs.len() {
            result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
        }
        
        result
    }
}

impl Neg for Polynomial {
    type Output = Self;
    
    fn neg(self) -> Self {
        let mut result = self.clone();
        for i in 0..self.coeffs.len() {
            result.coeffs[i] = -self.coeffs[i];
        }
        
        result
    }
}

impl fmt::Display for Polynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for (i, coeff) in self.coeffs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", coeff.value())?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_modulus() -> PolyModulusInfo {
        PolyModulusInfo {
            degree: 4,
            q: 13,
            is_ntt_form: false,
        }
    }
    
    fn create_test_poly(coeffs: &[i32]) -> Polynomial {
        let modulus = create_test_modulus();
        let q = modulus.q;
        let coeffs = coeffs.iter().map(|&c| ZqElement::new(c, q)).collect();
        Polynomial::new(coeffs, modulus)
    }
    
    #[test]
    fn test_addition() {
        let p1 = create_test_poly(&[1, 2, 3, 4]);
        let p2 = create_test_poly(&[5, 6, 7, 8]);
        let result = p1 + p2;
        
        let expected = create_test_poly(&[6, 8, 10, 12]);
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_subtraction() {
        let p1 = create_test_poly(&[10, 11, 12, 0]);
        let p2 = create_test_poly(&[1, 3, 5, 7]);
        let result = p1 - p2;
        
        let expected = create_test_poly(&[9, 8, 7, 6]);
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_schoolbook_mul() {
        let p1 = create_test_poly(&[1, 2, 0, 0]);
        let p2 = create_test_poly(&[3, 4, 0, 0]);
        let result = p1.schoolbook_mul(&p2);
        
        // (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2
        // In Z_13[x]/(x^4+1), this is 3 + 10x + 8x^2 + 0x^3
        let expected = create_test_poly(&[3, 10, 8, 0]);
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_scalar_mul() {
        let poly = create_test_poly(&[1, 2, 3, 4]);
        let scalar = ZqElement::new(2, 13);
        let result = poly.scalar_mul(scalar);
        
        let expected = create_test_poly(&[2, 4, 6, 8]);
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_byte_conversion() {
        let poly = create_test_poly(&[1, 2, 3, 4]);
        let bytes = poly.to_bytes(4); // 4 bits per coefficient
        let reconstructed = Polynomial::from_bytes(&bytes, create_test_modulus(), 4);
        
        assert_eq!(poly, reconstructed);
    }
    
    #[test]
    fn test_compress_decompress() {
        let poly = create_test_poly(&[1, 5, 9, 12]);
        let compressed = poly.compress(3); // Compress to 3 bits
        let decompressed = compressed.decompress(13); // Decompress back to 13
        
        // Note: compression/decompression introduces rounding errors,
        // so we don't expect exact equality
        for (orig, decomp) in poly.coeffs.iter().zip(decompressed.coeffs.iter()) {
            let diff = (orig.value() - decomp.value()).abs();
            assert!(diff <= 1, "Compression/decompression difference too large");
        }
    }
    
    #[test]
    fn test_high_low_bits() {
        let poly = create_test_poly(&[1, 5, 9, 12]);
        let gamma2 = 4;
        
        let high = poly.high_bits(gamma2);
        let low = poly.low_bits(gamma2);
        
        // Verify we can reconstruct original values
        for i in 0..poly.coeffs.len() {
            let h = high.coeffs[i].value();
            let l = low.coeffs[i].value();
            let reconstructed = (h * gamma2 + l) % poly.modulus_info.q;
            
            // Need to handle negative low bits
            let orig = poly.coeffs[i].value();
            let diff = (orig - reconstructed).abs();
            assert!(diff <= 1, "High/low bits reconstruction difference too large");
        }
    }
    
    #[test]
    fn test_infinity_norm() {
        let modulus = PolyModulusInfo {
            degree: 4,
            q: 17,
            is_ntt_form: false,
        };
        
        let q = modulus.q;
        let mut coeffs = vec![
            ZqElement::new(2, q),
            ZqElement::new(16, q), // This is -1 mod 17
            ZqElement::new(5, q),
            ZqElement::new(10, q),
        ];
        
        let poly = Polynomial::new(coeffs, modulus);
        let norm = poly.infinity_norm();
        
        // Max should be 10 vs 17/2 = 8.5, so centered to -7
        assert_eq!(norm, 7);
    }
} 