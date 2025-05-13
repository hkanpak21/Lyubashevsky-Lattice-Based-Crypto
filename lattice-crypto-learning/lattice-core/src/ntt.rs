use crate::polynomial::Polynomial;
use crate::params::PolyModulusInfo;
use crate::zq::ZqElement;

/// Represents precomputed values for Number Theoretic Transform
#[derive(Debug, Clone)]
pub struct NTTParams {
    /// Modulus q
    pub q: i32,
    /// Degree of polynomial X^n + 1
    pub n: usize,
    /// n-th primitive root of unity
    pub psi: i32,
    /// Inverse of n modulo q
    pub n_inv: i32,
    /// Forward NTT precomputed roots (twiddle factors)
    pub roots_of_unity: Vec<i32>,
    /// Inverse NTT precomputed roots
    pub inv_roots_of_unity: Vec<i32>,
    /// Barrett reduction precomputed factor
    pub barrett_factor: i64,
    /// Barrett reduction shift
    pub barrett_shift: u32,
}

impl NTTParams {
    /// Creates precomputed NTT parameters for a given modulus q and degree n
    /// Precondition: n is a power of 2
    pub fn new(q: i32, n: usize, psi: i32) -> Self {
        assert!(n.is_power_of_two(), "n must be a power of 2");
        
        // Compute n_inv
        let n_inv = self::mod_inverse(n as i32, q);
        
        // Precompute roots of unity
        let roots_of_unity = self::precompute_roots(psi, n, q);
        
        // Precompute inverse roots of unity
        let psi_inv = self::mod_inverse(psi, q);
        let inv_roots_of_unity = self::precompute_roots(psi_inv, n, q);
        
        // Precompute Barrett reduction factor
        let barrett_shift = 32; // Adjust as needed for performance
        let barrett_factor = ZqElement::barrett_factor(q, barrett_shift);
        
        NTTParams {
            q,
            n,
            psi,
            n_inv,
            roots_of_unity,
            inv_roots_of_unity,
            barrett_factor,
            barrett_shift,
        }
    }
}

/// Performs forward Number Theoretic Transform (NTT) on a polynomial
pub fn ntt_forward(poly: &Polynomial, params: &NTTParams) -> Polynomial {
    assert_eq!(poly.modulus_info.degree, params.n,
              "Polynomial degree must match NTT params");
    assert_eq!(poly.modulus_info.q, params.q,
              "Polynomial modulus must match NTT params");
    
    // Create modulus info for the NTT-domain polynomial
    let ntt_modulus_info = PolyModulusInfo {
        degree: params.n,
        q: params.q,
        is_ntt_form: true,
    };
    
    // Copy coefficients to work with
    let mut coeffs: Vec<ZqElement> = poly.coeffs.clone();
    
    // Perform in-place FFT-like NTT
    butterfly_ntt(&mut coeffs, params);
    
    // Return the transformed polynomial
    Polynomial {
        coeffs,
        modulus_info: ntt_modulus_info,
    }
}

/// Performs inverse Number Theoretic Transform (NTT) on a polynomial
pub fn ntt_inverse(poly: &Polynomial, params: &NTTParams) -> Polynomial {
    assert!(poly.modulus_info.is_ntt_form,
           "Polynomial must be in NTT form for inverse NTT");
    assert_eq!(poly.modulus_info.degree, params.n,
              "Polynomial degree must match NTT params");
    assert_eq!(poly.modulus_info.q, params.q,
              "Polynomial modulus must match NTT params");
    
    // Create modulus info for the standard-domain polynomial
    let std_modulus_info = PolyModulusInfo {
        degree: params.n,
        q: params.q,
        is_ntt_form: false,
    };
    
    // Copy coefficients to work with
    let mut coeffs: Vec<ZqElement> = poly.coeffs.clone();
    
    // Perform in-place inverse NTT
    butterfly_intt(&mut coeffs, params);
    
    // Return the transformed polynomial
    Polynomial {
        coeffs,
        modulus_info: std_modulus_info,
    }
}

/// Multiplies two polynomials in NTT domain (component-wise multiplication)
pub fn ntt_pointwise_mul(poly1: &Polynomial, poly2: &Polynomial) -> Polynomial {
    assert!(poly1.modulus_info.is_ntt_form && poly2.modulus_info.is_ntt_form,
           "Both polynomials must be in NTT form for pointwise multiplication");
    assert_eq!(poly1.modulus_info.degree, poly2.modulus_info.degree,
              "Polynomials must have the same degree");
    assert_eq!(poly1.modulus_info.q, poly2.modulus_info.q,
              "Polynomials must have the same modulus");
    
    let n = poly1.modulus_info.degree;
    let q = poly1.modulus_info.q;
    let mut result_coeffs = Vec::with_capacity(n);
    
    for i in 0..n {
        result_coeffs.push(poly1.coeffs[i] * poly2.coeffs[i]);
    }
    
    Polynomial {
        coeffs: result_coeffs,
        modulus_info: PolyModulusInfo {
            degree: n,
            q,
            is_ntt_form: true,
        },
    }
}

/// Implements polynomial multiplication using NTT
/// a * b = InvNTT(NTT(a) ∘ NTT(b)) where ∘ is pointwise multiplication
pub fn ntt_polynomial_mul(poly1: &Polynomial, poly2: &Polynomial, params: &NTTParams) -> Polynomial {
    assert_eq!(poly1.modulus_info.degree, params.n,
              "Polynomial degree must match NTT params");
    assert_eq!(poly2.modulus_info.degree, params.n,
              "Polynomial degree must match NTT params");
    
    // Check if polynomials are already in NTT form
    let ntt_poly1 = if poly1.modulus_info.is_ntt_form {
        poly1.clone()
    } else {
        ntt_forward(poly1, params)
    };
    
    let ntt_poly2 = if poly2.modulus_info.is_ntt_form {
        poly2.clone()
    } else {
        ntt_forward(poly2, params)
    };
    
    // Pointwise multiplication in NTT domain
    let ntt_product = ntt_pointwise_mul(&ntt_poly1, &ntt_poly2);
    
    // Inverse NTT to get the polynomial product
    ntt_inverse(&ntt_product, params)
}

/// Helper function to compute modular inverse using Extended Euclidean Algorithm
fn mod_inverse(a: i32, m: i32) -> i32 {
    let mut s = 0;
    let mut old_s = 1;
    let mut t = 1;
    let mut old_t = 0;
    let mut r = m;
    let mut old_r = a;
    
    while r != 0 {
        let quotient = old_r / r;
        
        let temp = r;
        r = old_r - quotient * r;
        old_r = temp;
        
        let temp = s;
        s = old_s - quotient * s;
        old_s = temp;
        
        let temp = t;
        t = old_t - quotient * t;
        old_t = temp;
    }
    
    // Ensure the result is positive
    let result = if old_s < 0 { old_s + m } else { old_s };
    result
}

/// Helper function to compute modular exponentiation
fn mod_pow(base: i32, exponent: usize, modulus: i32) -> i32 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exp = exponent;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result as i64 * base as i64) as i32 % modulus;
        }
        base = (base as i64 * base as i64) as i32 % modulus;
        exp >>= 1;
    }
    
    result
}

/// Precomputes roots of unity for NTT
fn precompute_roots(psi: i32, n: usize, q: i32) -> Vec<i32> {
    let mut roots = Vec::with_capacity(n);
    let log_n = n.trailing_zeros();
    
    // psi^(2n/4), psi^(2n/8), ... - powers of psi for butterfly operations
    for i in 0..n {
        // Bit-reversed order for more efficient in-place NTT
        let j = bit_reverse(i, log_n);
        let power = (j * n / 2) % n;
        let root = mod_pow(psi, power, q);
        roots.push(root);
    }
    
    roots
}

/// Implements the bit-reversal permutation for efficient in-place NTT
fn bit_reverse(mut index: usize, bits: u32) -> usize {
    let mut reversed = 0;
    
    for i in 0..bits {
        reversed |= ((index >> i) & 1) << (bits - 1 - i);
    }
    
    reversed
}

/// Performs in-place forward NTT using the cooley-tukey algorithm
fn butterfly_ntt(coeffs: &mut Vec<ZqElement>, params: &NTTParams) {
    let n = params.n;
    let q = params.q;
    let log_n = n.trailing_zeros() as usize;
    
    // Bit-reversal permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n as u32);
        if i < j {
            coeffs.swap(i, j);
        }
    }
    
    // NTT butterfly operations
    let mut len = 2;
    for _ in 0..log_n {
        let half_len = len / 2;
        
        for j in (0..n).step_by(len) {
            for i in 0..half_len {
                let odd_idx = j + i + half_len;
                let even_idx = j + i;
                
                let odd = coeffs[odd_idx];
                let even = coeffs[even_idx];
                
                // Get twiddle factor
                let factor = ZqElement::new(params.roots_of_unity[half_len + i], q);
                
                // Butterfly operation: (even, odd) -> (even + odd*factor, even - odd*factor)
                let temp = odd * factor;
                coeffs[odd_idx] = even - temp;
                coeffs[even_idx] = even + temp;
            }
        }
        
        len *= 2;
    }
}

/// Performs in-place inverse NTT using the gentlemen-sande algorithm
fn butterfly_intt(coeffs: &mut Vec<ZqElement>, params: &NTTParams) {
    let n = params.n;
    let q = params.q;
    let log_n = n.trailing_zeros() as usize;
    
    // Inverse NTT butterfly operations
    let mut len = n;
    for _ in 0..log_n {
        let half_len = len / 2;
        
        for j in (0..n).step_by(len) {
            for i in 0..half_len {
                let odd_idx = j + i + half_len;
                let even_idx = j + i;
                
                let even = coeffs[even_idx];
                let odd = coeffs[odd_idx];
                
                // Butterfly operation: (even, odd) -> ((even + odd)/2, (even - odd)/2 * factor)
                coeffs[even_idx] = even + odd;
                
                let diff = even - odd;
                
                // Get twiddle factor
                let factor = ZqElement::new(params.inv_roots_of_unity[half_len + i], q);
                
                coeffs[odd_idx] = diff * factor;
            }
        }
        
        len /= 2;
    }
    
    // Bit-reversal permutation
    for i in 0..n {
        let j = bit_reverse(i, log_n as u32);
        if i < j {
            coeffs.swap(i, j);
        }
    }
    
    // Multiply by n^-1 mod q
    let n_inv = ZqElement::new(params.n_inv, q);
    for i in 0..n {
        coeffs[i] = coeffs[i] * n_inv;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::PolyModulusInfo;
    
    fn create_test_params(n: usize) -> (PolyModulusInfo, NTTParams) {
        // For testing we'll use q = 97 (a small prime) and n = 8
        let q = 97;
        
        // Find a 2n-th primitive root of unity
        // For q = 97 and n = 8, we can use psi = 13
        let psi = 13;
        
        let modulus_info = PolyModulusInfo {
            degree: n,
            q,
            is_ntt_form: false,
        };
        
        let ntt_params = NTTParams::new(q, n, psi);
        
        (modulus_info, ntt_params)
    }
    
    fn create_test_poly(coeffs: &[i32], modulus_info: PolyModulusInfo) -> Polynomial {
        let q = modulus_info.q;
        let coeffs: Vec<ZqElement> = coeffs.iter()
            .map(|&c| ZqElement::new(c, q))
            .collect();
        
        Polynomial::new(coeffs, modulus_info)
    }
    
    #[test]
    fn test_ntt_roundtrip() {
        let n = 8;
        let (modulus_info, ntt_params) = create_test_params(n);
        
        let poly = create_test_poly(&[1, 2, 3, 4, 5, 6, 7, 8], modulus_info);
        
        // Apply forward NTT
        let ntt_poly = ntt_forward(&poly, &ntt_params);
        
        // Apply inverse NTT
        let reconstructed = ntt_inverse(&ntt_poly, &ntt_params);
        
        // Check that we get the original polynomial back
        for i in 0..n {
            assert_eq!(poly.coeffs[i].value(), reconstructed.coeffs[i].value());
        }
    }
    
    #[test]
    fn test_ntt_polynomial_multiplication() {
        let n = 8;
        let (modulus_info, ntt_params) = create_test_params(n);
        
        let poly1 = create_test_poly(&[1, 2, 0, 0, 0, 0, 0, 0], modulus_info);
        let poly2 = create_test_poly(&[3, 4, 0, 0, 0, 0, 0, 0], modulus_info);
        
        // Compute product using NTT
        let ntt_product = ntt_polynomial_mul(&poly1, &poly2, &ntt_params);
        
        // Compute product using schoolbook for comparison
        let schoolbook_product = poly1.schoolbook_mul(&poly2);
        
        // Check that both methods give the same result
        for i in 0..n {
            assert_eq!(ntt_product.coeffs[i].value(), schoolbook_product.coeffs[i].value());
        }
    }
    
    #[test]
    fn test_bit_reversal() {
        assert_eq!(bit_reverse(0, 3), 0);
        assert_eq!(bit_reverse(1, 3), 4);
        assert_eq!(bit_reverse(2, 3), 2);
        assert_eq!(bit_reverse(3, 3), 6);
        assert_eq!(bit_reverse(4, 3), 1);
        assert_eq!(bit_reverse(5, 3), 5);
        assert_eq!(bit_reverse(6, 3), 3);
        assert_eq!(bit_reverse(7, 3), 7);
    }
    
    #[test]
    fn test_mod_inverse() {
        // Test some known inverses
        assert_eq!(mod_inverse(3, 11), 4);  // 3 * 4 = 12 ≡ 1 (mod 11)
        assert_eq!(mod_inverse(5, 11), 9);  // 5 * 9 = 45 ≡ 1 (mod 11)
        
        // Test with our NTT parameters
        let (_, ntt_params) = create_test_params(8);
        let psi_inv = mod_inverse(ntt_params.psi, ntt_params.q);
        
        let product = (ntt_params.psi as i64 * psi_inv as i64) % ntt_params.q as i64;
        assert_eq!(product, 1);
    }
} 