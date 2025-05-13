use rand::{Rng, SeedableRng};
use rand::distributions::{Distribution, Uniform};
use rand_chacha::ChaCha20Rng;
use crate::params::PolyModulusInfo;
use crate::polynomial::Polynomial;
use crate::zq::ZqElement;
use sha3::{Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Samples uniformly from the range [min, max]
pub fn sample_uniform(min: i32, max: i32, rng: &mut impl Rng) -> i32 {
    let distribution = Uniform::new_inclusive(min, max);
    distribution.sample(rng)
}

/// Samples a uniform polynomial with coefficients in [-β, β]
pub fn sample_uniform_poly(beta: i32, modulus_info: PolyModulusInfo, rng: &mut impl Rng) -> Polynomial {
    let n = modulus_info.degree;
    let q = modulus_info.q;
    let mut coeffs = Vec::with_capacity(n);
    
    let distribution = Uniform::new_inclusive(-beta, beta);
    for _ in 0..n {
        let value = distribution.sample(rng);
        coeffs.push(ZqElement::new(value, q));
    }
    
    Polynomial::new(coeffs, modulus_info)
}

/// Samples a uniform polynomial with coefficients in [0, q-1]
pub fn sample_uniform_poly_zq(modulus_info: PolyModulusInfo, rng: &mut impl Rng) -> Polynomial {
    let n = modulus_info.degree;
    let q = modulus_info.q;
    let mut coeffs = Vec::with_capacity(n);
    
    let distribution = Uniform::new(0, q);
    for _ in 0..n {
        let value = distribution.sample(rng);
        coeffs.push(ZqElement::new(value, q));
    }
    
    Polynomial::new(coeffs, modulus_info)
}

/// Samples from the binomial distribution ψ_η (Definition 8 in the paper)
/// This simulates sampling from a discrete Gaussian.
pub fn sample_binomial(eta: usize, modulus_info: PolyModulusInfo, rng: &mut impl Rng) -> Polynomial {
    let n = modulus_info.degree;
    let q = modulus_info.q;
    let mut coeffs = Vec::with_capacity(n);
    
    for _ in 0..n {
        // Sample 2η bits and count the Hamming weight difference
        let mut a_bits = 0;
        let mut b_bits = 0;
        
        for _ in 0..eta {
            a_bits += if rng.gen::<bool>() { 1 } else { 0 };
            b_bits += if rng.gen::<bool>() { 1 } else { 0 };
        }
        
        // The difference follows a binomial distribution with mean 0 and width η
        let value = a_bits as i32 - b_bits as i32;
        coeffs.push(ZqElement::new(value, q));
    }
    
    Polynomial::new(coeffs, modulus_info)
}

/// Samples a polynomial with exactly tau coefficients set to ±1, rest are 0
/// Used for challenge sampling in Dilithium (SampleInBall)
pub fn sample_challenge(tau: usize, modulus_info: PolyModulusInfo, rng: &mut impl Rng) -> Polynomial {
    let n = modulus_info.degree;
    let q = modulus_info.q;
    
    // Initialize with all zeros
    let mut values = vec![0i32; n];
    
    // Positions that will be set to ±1
    let mut positions: Vec<usize> = (0..n).collect();
    
    // Fisher-Yates shuffle to pick tau random positions
    for i in 0..tau {
        let j = i + rng.gen_range(0..n - i);
        positions.swap(i, j);
    }
    
    // Set the chosen positions to ±1
    for i in 0..tau {
        values[positions[i]] = if rng.gen::<bool>() { 1 } else { -1 };
    }
    
    // Create polynomial
    let coeffs = values.into_iter()
        .map(|v| ZqElement::new(v, q))
        .collect();
    
    Polynomial::new(coeffs, modulus_info)
}

/// Deterministically generates a pseudorandom matrix A from a seed for Kyber/Dilithium
pub fn expand_matrix(rho: &[u8], k: usize, l: usize, modulus_info: PolyModulusInfo) -> Vec<Vec<Polynomial>> {
    let mut matrix = Vec::with_capacity(k);
    
    for i in 0..k {
        let mut row = Vec::with_capacity(l);
        for j in 0..l {
            // Use i,j,rho as a seed for the polynomial
            let poly = expand_poly(rho, i as u8, j as u8, modulus_info);
            row.push(poly);
        }
        matrix.push(row);
    }
    
    matrix
}

/// Deterministically generates a pseudorandom polynomial from a seed and indices
pub fn expand_poly(rho: &[u8], i: u8, j: u8, modulus_info: PolyModulusInfo) -> Polynomial {
    let n = modulus_info.degree;
    let q = modulus_info.q;
    let mut coeffs = Vec::with_capacity(n);
    
    // Create seed = rho || i || j
    let mut seed = rho.to_vec();
    seed.push(i);
    seed.push(j);
    
    // Use SHAKE-128 to expand the seed into coefficients
    let mut shake = Shake128::default();
    shake.update(&seed);
    let mut reader = shake.finalize_xof();
    
    // Extract n coefficients from the XOF
    let mut bytes = [0u8; 2];
    for _ in 0..n {
        reader.read(&mut bytes);
        
        // Convert 2 bytes to a coefficient mod q
        let value = u16::from_le_bytes(bytes) as i32 % q;
        coeffs.push(ZqElement::new(value, q));
    }
    
    Polynomial::new(coeffs, modulus_info)
}

/// Implements PRF(seed, nonce, len) function used in various schemes
pub fn prf(seed: &[u8], nonce: u16, len: usize) -> Vec<u8> {
    let mut input = seed.to_vec();
    
    // Append nonce in little-endian format
    let nonce_bytes = nonce.to_le_bytes();
    input.extend_from_slice(&nonce_bytes);
    
    // Use SHAKE-256 to generate output
    let mut shake = Shake256::default();
    shake.update(&input);
    let mut reader = shake.finalize_xof();
    
    let mut output = vec![0u8; len];
    reader.read(&mut output);
    
    output
}

/// Samples a polynomial with coefficients from a seed using PRF
pub fn sample_poly_from_seed(seed: &[u8], modulus_info: PolyModulusInfo, eta: usize) -> Polynomial {
    let n = modulus_info.degree;
    let q = modulus_info.q;
    
    // Generate random bytes
    let bytes_needed = n * eta.div_ceil(8); // Each coefficient needs about η bits
    let random_bytes = prf(seed, 0, bytes_needed);
    
    // Derive polynomial coefficients
    let mut coeffs = Vec::with_capacity(n);
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]); // Just a placeholder RNG
    
    // Use the random bytes to seed our RNG
    let mut seed_array = [0u8; 32];
    for (i, &byte) in random_bytes.iter().take(32).enumerate() {
        seed_array[i] = byte;
    }
    rng = ChaCha20Rng::from_seed(seed_array);
    
    // Sample coefficients according to distribution
    if eta == 1 {
        // Special case for η=1: direct ternary sampling {-1, 0, 1}
        for _ in 0..n {
            let r = rng.gen_range(0..3) as i32;
            let value = if r == 0 { -1 } else if r == 1 { 0 } else { 1 };
            coeffs.push(ZqElement::new(value, q));
        }
    } else {
        // Use binomial sampling for η>1
        for _ in 0..n {
            let mut a_bits = 0;
            let mut b_bits = 0;
            
            for _ in 0..eta {
                a_bits += if rng.gen::<bool>() { 1 } else { 0 };
                b_bits += if rng.gen::<bool>() { 1 } else { 0 };
            }
            
            let value = a_bits as i32 - b_bits as i32;
            coeffs.push(ZqElement::new(value, q));
        }
    }
    
    Polynomial::new(coeffs, modulus_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    /// Creates a test PolyModulusInfo
    fn create_test_modulus() -> PolyModulusInfo {
        PolyModulusInfo {
            degree: 8,
            q: 97,
            is_ntt_form: false,
        }
    }
    
    #[test]
    fn test_uniform_sampling() {
        let mut rng = thread_rng();
        let samples = (0..1000)
            .map(|_| sample_uniform(-5, 5, &mut rng))
            .collect::<Vec<_>>();
        
        // Verify range
        assert!(samples.iter().all(|&x| x >= -5 && x <= 5));
        
        // Verify that we have at least some of each value
        for i in -5..=5 {
            assert!(samples.contains(&i), "Sample should contain {}", i);
        }
    }
    
    #[test]
    fn test_uniform_poly() {
        let mut rng = thread_rng();
        let modulus = create_test_modulus();
        let beta = 3;
        
        let poly = sample_uniform_poly(beta, modulus, &mut rng);
        
        // Verify coefficients are in range
        for coeff in &poly.coeffs {
            let centered = if coeff.value() > modulus.q / 2 {
                coeff.value() - modulus.q
            } else {
                coeff.value()
            };
            assert!(centered >= -beta && centered <= beta);
        }
    }
    
    #[test]
    fn test_binomial_sampling() {
        let mut rng = thread_rng();
        let modulus = create_test_modulus();
        let eta = 3;
        
        let poly = sample_binomial(eta, modulus, &mut rng);
        
        // Verify coefficients are in range [-η, η]
        for coeff in &poly.coeffs {
            let centered = if coeff.value() > modulus.q / 2 {
                coeff.value() - modulus.q
            } else {
                coeff.value()
            };
            assert!(centered >= -(eta as i32) && centered <= eta as i32);
        }
    }
    
    #[test]
    fn test_challenge_sampling() {
        let mut rng = thread_rng();
        let modulus = create_test_modulus();
        let tau = 3;
        
        let poly = sample_challenge(tau, modulus, &mut rng);
        
        // Count non-zero coefficients
        let non_zero_count = poly.coeffs.iter()
            .filter(|c| c.value() != 0)
            .count();
        
        // Verify exactly tau non-zero coefficients
        assert_eq!(non_zero_count, tau);
        
        // Verify all non-zero coefficients are ±1
        for coeff in &poly.coeffs {
            let value = coeff.value();
            assert!(value == 0 || value == 1 || value == modulus.q - 1); // 0, 1, or -1 mod q
        }
    }
    
    #[test]
    fn test_expand_matrix() {
        let rho = b"test_seed_for_matrix_expansion";
        let k = 2;
        let l = 3;
        let modulus = create_test_modulus();
        
        let matrix = expand_matrix(rho, k, l, modulus);
        
        // Verify dimensions
        assert_eq!(matrix.len(), k);
        for row in &matrix {
            assert_eq!(row.len(), l);
        }
        
        // Verify deterministic generation
        let matrix2 = expand_matrix(rho, k, l, modulus);
        for i in 0..k {
            for j in 0..l {
                assert_eq!(matrix[i][j].coeffs, matrix2[i][j].coeffs);
            }
        }
    }
    
    #[test]
    fn test_prf() {
        let seed = b"test_seed_for_prf";
        let nonce1 = 1u16;
        let nonce2 = 2u16;
        
        let output1 = prf(seed, nonce1, 32);
        let output2 = prf(seed, nonce1, 32);
        let output3 = prf(seed, nonce2, 32);
        
        // Verify deterministic for same seed/nonce
        assert_eq!(output1, output2);
        
        // Verify different for different nonce
        assert_ne!(output1, output3);
    }
} 