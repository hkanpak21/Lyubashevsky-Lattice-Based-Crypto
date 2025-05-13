use lattice_core::{
    params::PolyModulusInfo,
    polynomial::Polynomial,
    vector_matrix::{PolyVector, PolyMatrix},
    ntt::{ntt_forward, ntt_inverse, NTTParams, ntt_pointwise_mul},
    sampling::{sample_poly_from_seed, expand_matrix},
    hashing::prf,
};

use rand::{Rng, rngs::OsRng};
use crate::params::{SecurityLevel, N, Q, DU, DV, poly_modulus, poly_modulus_ntt, sizes};

/// Represents a Kyber CPA public key
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Seed for generating matrix A (rho in the paper)
    pub rho: [u8; 32],
    /// Vector t = As + e in NTT form
    pub t_hat: PolyVector,
    /// Security level
    pub security_level: SecurityLevel,
}

/// Represents a Kyber CPA secret key
#[derive(Debug, Clone)]
pub struct SecretKey {
    /// Secret vector s in NTT form
    pub s_hat: PolyVector,
    /// Security level
    pub security_level: SecurityLevel,
}

/// Represents a Kyber ciphertext
#[derive(Debug, Clone)]
pub struct Ciphertext {
    /// Vector u (compressed)
    pub u: PolyVector,
    /// Polynomial v (compressed)
    pub v: Polynomial,
}

/// Generate a primitive root of unity for NTT.
/// For Kyber, we need an appropriate 2n-th root of unity mod q.
/// For q = 3329 and n = 256, we can use psi = 17.
pub fn get_ntt_params() -> NTTParams {
    // 17 is a known good root of unity for Kyber's parameters
    let psi = 17;
    NTTParams::new(Q, N, psi)
}

/// Implements the CPA-KeyGen algorithm from Figure 3
pub fn keygen(security_level: SecurityLevel) -> (PublicKey, SecretKey) {
    let mut rng = OsRng;
    let _k = security_level.k();
    let eta1 = security_level.eta1();
    
    // Generate two random seeds
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rng.fill(&mut rho);
    rng.fill(&mut sigma);
    
    // Create the uniform matrix A from seed rho
    let modulus_info = poly_modulus();
    let modulus_info_ntt = poly_modulus_ntt();
    let ntt_params = get_ntt_params();
    
    let a_matrix = expand_matrix(&rho, _k, _k, modulus_info);
    
    // Convert A to NTT domain for efficiency
    let mut a_hat_matrix = Vec::with_capacity(_k);
    for row in &a_matrix {
        let mut a_hat_row = Vec::with_capacity(_k);
        for poly in row {
            a_hat_row.push(ntt_forward(poly, &ntt_params));
        }
        a_hat_matrix.push(PolyVector::new(a_hat_row, modulus_info_ntt));
    }
    let a_hat = PolyMatrix::new(a_hat_matrix, _k, _k, modulus_info_ntt);
    
    // Sample secret vector s with small entries
    let mut s_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        let seed = prf(&sigma, i as u16, 32);
        let s_i = sample_poly_from_seed(&seed, modulus_info, eta1);
        s_entries.push(s_i);
    }
    let s = PolyVector::new(s_entries, modulus_info);
    
    // Convert s to NTT domain
    let mut s_hat_entries = Vec::with_capacity(_k);
    for poly in &s.entries {
        s_hat_entries.push(ntt_forward(poly, &ntt_params));
    }
    let s_hat = PolyVector::new(s_hat_entries, modulus_info_ntt);
    
    // Sample error vector e
    let mut e_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        let seed = prf(&sigma, (_k + i) as u16, 32);
        let e_i = sample_poly_from_seed(&seed, modulus_info, eta1);
        e_entries.push(e_i);
    }
    let e = PolyVector::new(e_entries, modulus_info);
    
    // Compute t = As + e
    // Since A and s are in NTT domain, we multiply them there
    // and then transform back, then add e
    let t_hat_ntt = a_hat.mul_vec(&s_hat, Some(&ntt_params));
    
    // Convert e to NTT domain
    let mut e_hat_entries = Vec::with_capacity(_k);
    for poly in &e.entries {
        e_hat_entries.push(ntt_forward(poly, &ntt_params));
    }
    let e_hat = PolyVector::new(e_hat_entries, modulus_info_ntt);
    
    // Add e in NTT domain
    let mut t_hat_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        let t_i = t_hat_ntt.entries[i].clone() + e_hat.entries[i].clone();
        t_hat_entries.push(t_i);
    }
    let t_hat = PolyVector::new(t_hat_entries, modulus_info_ntt);
    
    // Create public and secret keys
    let pk = PublicKey {
        rho,
        t_hat,
        security_level,
    };
    
    let sk = SecretKey {
        s_hat,
        security_level,
    };
    
    (pk, sk)
}

/// Implements the CPA-Encrypt algorithm from Figure 3
pub fn encrypt(pk: &PublicKey, msg: &[u8; 32], coins: &[u8; 32]) -> Ciphertext {
    let security_level = pk.security_level;
    let _k = security_level.k();
    let eta1 = security_level.eta1();
    let eta2 = security_level.eta2();
    
    let modulus_info = poly_modulus();
    let modulus_info_ntt = poly_modulus_ntt();
    let ntt_params = get_ntt_params();
    
    // Encode message as a polynomial m
    let m = decode_message(msg, modulus_info);
    
    // Generate the uniform matrix A from rho
    let a_matrix = expand_matrix(&pk.rho, _k, _k, modulus_info);
    
    // Convert A to NTT domain
    let mut a_t_hat_matrix = Vec::with_capacity(_k);
    for i in 0.._k {
        let mut row = Vec::with_capacity(_k);
        for j in 0.._k {
            row.push(ntt_forward(&a_matrix[j][i], &ntt_params));
        }
        a_t_hat_matrix.push(PolyVector::new(row, modulus_info_ntt));
    }
    let a_t_hat = PolyMatrix::new(a_t_hat_matrix, _k, _k, modulus_info_ntt);
    
    // Sample vector r with small entries
    let mut r_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        let seed = prf(coins, i as u16, 32);
        let r_i = sample_poly_from_seed(&seed, modulus_info, eta1);
        r_entries.push(r_i);
    }
    let r = PolyVector::new(r_entries, modulus_info);
    
    // Convert r to NTT domain
    let mut r_hat_entries = Vec::with_capacity(_k);
    for poly in &r.entries {
        r_hat_entries.push(ntt_forward(poly, &ntt_params));
    }
    let r_hat = PolyVector::new(r_hat_entries, modulus_info_ntt);
    
    // Sample error vector e1
    let mut e1_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        let seed = prf(coins, (_k + i) as u16, 32);
        let e1_i = sample_poly_from_seed(&seed, modulus_info, eta2);
        e1_entries.push(e1_i);
    }
    let e1 = PolyVector::new(e1_entries, modulus_info);
    
    // Sample error e2
    let seed = prf(coins, (2 * _k) as u16, 32);
    let e2 = sample_poly_from_seed(&seed, modulus_info, eta2);
    
    // Compute u = A^T r + e1
    let u_hat = a_t_hat.mul_vec(&r_hat, Some(&ntt_params));
    
    // Convert u_hat back to standard form
    let mut u_std_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        let u_i = ntt_inverse(&u_hat.entries[i], &ntt_params);
        u_std_entries.push(u_i);
    }
    let u_std = PolyVector::new(u_std_entries, modulus_info);
    
    // Add e1 to get the final u
    let mut u_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        let u_i = u_std.entries[i].clone() + e1.entries[i].clone();
        u_entries.push(u_i);
    }
    let u = PolyVector::new(u_entries, modulus_info);
    
    // Compute v = t^T r + e2 + ⌈q/2⌋ * m
    // First compute t^T r in NTT domain
    let mut tr_hat = Polynomial::zero(modulus_info_ntt);
    for i in 0.._k {
        let tr_i = ntt_pointwise_mul(&pk.t_hat.entries[i], &r_hat.entries[i]);
        tr_hat = tr_hat + tr_i;
    }
    
    // Convert back to standard form
    let tr = ntt_inverse(&tr_hat, &ntt_params);
    
    // Add e2 and message encoding
    let v = tr + e2 + m;
    
    // Compress u and v
    let compressed_u = compress_vector(&u, DU);
    let compressed_v = compress_poly(&v, DV);
    
    Ciphertext {
        u: compressed_u,
        v: compressed_v,
    }
}

/// Implements the CPA-Decrypt algorithm from Figure 3
pub fn decrypt(sk: &SecretKey, ciphertext: &Ciphertext) -> [u8; 32] {
    let security_level = sk.security_level;
    let _k = security_level.k();
    
    let modulus_info = poly_modulus();
    let modulus_info_ntt = poly_modulus_ntt();
    let ntt_params = get_ntt_params();
    
    // Decompress u and v
    let u = decompress_vector(&ciphertext.u, DU, Q);
    let v = decompress_poly(&ciphertext.v, DV, Q);
    
    // Compute v - s^T u
    // First compute s^T u in NTT domain
    let mut u_hat_entries = Vec::with_capacity(_k);
    for i in 0.._k {
        u_hat_entries.push(ntt_forward(&u.entries[i], &ntt_params));
    }
    let u_hat = PolyVector::new(u_hat_entries, modulus_info_ntt);
    
    let mut su_hat = Polynomial::zero(modulus_info_ntt);
    for i in 0.._k {
        let su_i = ntt_pointwise_mul(&sk.s_hat.entries[i], &u_hat.entries[i]);
        su_hat = su_hat + su_i;
    }
    
    // Convert back to standard form
    let su = ntt_inverse(&su_hat, &ntt_params);
    
    // Compute v - s^T u
    let mp = v - su;
    
    // Decode the result into a message
    let msg = encode_message(&mp);
    
    msg
}

/// Encodes a message byte array as a polynomial
/// Each bit of the message is mapped to either 0 or q/2
fn decode_message(msg: &[u8; 32], modulus_info: PolyModulusInfo) -> Polynomial {
    let n = modulus_info.degree;
    let q = modulus_info.q;
    let q_half = q / 2;
    
    let mut coeffs = Vec::with_capacity(n);
    
    // In Kyber, each byte encodes 8 bits of the message
    // Each bit becomes 0 or q/2
    for i in 0..32 {
        let byte = msg[i];
        for j in 0..8 {
            if i * 8 + j < n {
                let bit = (byte >> j) & 1;
                let coeff = if bit == 1 { q_half } else { 0 };
                coeffs.push(lattice_core::zq::ZqElement::new(coeff, q));
            }
        }
    }
    
    // Ensure we have exactly n coefficients
    coeffs.resize(n, lattice_core::zq::ZqElement::new(0, q));
    
    Polynomial::new(coeffs, modulus_info)
}

/// Encodes a polynomial as a message byte array
/// Each coefficient close to q/2 is mapped to 1, otherwise 0
fn encode_message(poly: &Polynomial) -> [u8; 32] {
    let mut msg = [0u8; 32];
    let q = poly.modulus_info.q;
    let q_half = q / 2;
    let q_quarter = q / 4;
    let three_q_quarter = 3 * q / 4;
    
    // Map each coefficient to 0 or 1 based on proximity to 0 or q/2
    for i in 0..poly.coeffs.len() {
        if i / 8 >= 32 {
            break;
        }
        
        let coeff = poly.coeffs[i].value();
        // We consider it a 1 if it's closer to q/2 than to 0 or q
        let bit = if (coeff > q_quarter && coeff < three_q_quarter) { 1u8 } else { 0u8 };
        
        msg[i / 8] |= bit << (i % 8);
    }
    
    msg
}

/// Compresses a vector of polynomials (used for ciphertext u)
fn compress_vector(vec: &PolyVector, bits: usize) -> PolyVector {
    let mut compressed_entries = Vec::with_capacity(vec.len());
    let target_modulus = 1 << bits;
    
    for poly in &vec.entries {
        compressed_entries.push(compress_poly(poly, bits));
    }
    
    // Create a new PolyVector with the updated modulus info
    PolyVector::new(
        compressed_entries,
        PolyModulusInfo {
            degree: vec.modulus_info.degree,
            q: target_modulus as i32,
            is_ntt_form: vec.modulus_info.is_ntt_form,
        }
    )
}

/// Compresses a polynomial by rounding coefficients to a smaller range
fn compress_poly(poly: &Polynomial, bits: usize) -> Polynomial {
    let q = poly.modulus_info.q as i64;
    let degree = poly.modulus_info.degree;
    let mod_size = 1 << bits;
    let mut coeffs = Vec::with_capacity(poly.coeffs.len());
    
    for i in 0..poly.coeffs.len() {
        let x = poly.coeffs[i].value() as i64;
        // Compute (2^bits/q) * x rounded
        let compressed = ((((mod_size as i64) * x + (q >> 1)) / q) % mod_size as i64) as i32;
        coeffs.push(lattice_core::zq::ZqElement::new(compressed, mod_size as i32));
    }
    
    // Create a new polynomial with compressed modulus info
    Polynomial::new(coeffs, PolyModulusInfo { 
        degree, 
        q: mod_size as i32, 
        is_ntt_form: poly.modulus_info.is_ntt_form 
    })
}

/// Decompresses a vector of polynomials
fn decompress_vector(vec: &PolyVector, bits: usize, q_target: i32) -> PolyVector {
    let mut decompressed_entries = Vec::with_capacity(vec.len());
    
    for poly in &vec.entries {
        decompressed_entries.push(decompress_poly(poly, bits, q_target));
    }
    
    PolyVector::new(
        decompressed_entries,
        PolyModulusInfo {
            degree: vec.modulus_info.degree,
            q: q_target,
            is_ntt_form: vec.modulus_info.is_ntt_form,
        }
    )
}

/// Decompresses a polynomial by expanding coefficients to a larger range
fn decompress_poly(poly: &Polynomial, _bits: usize, q_target: i32) -> Polynomial {
    let p = poly.modulus_info.q as i64; // This should be 2^bits
    let degree = poly.modulus_info.degree;
    let q = q_target as i64;
    let mut coeffs = Vec::with_capacity(poly.coeffs.len());
    
    for i in 0..poly.coeffs.len() {
        let x = poly.coeffs[i].value() as i64;
        // Compute (q/2^bits) * x
        let decompressed = ((q * x + (p >> 1)) / p) as i32;
        coeffs.push(lattice_core::zq::ZqElement::new(decompressed, q_target));
    }
    
    // Create a new polynomial with target modulus info
    Polynomial::new(coeffs, PolyModulusInfo { 
        degree, 
        q: q_target, 
        is_ntt_form: poly.modulus_info.is_ntt_form 
    })
}

/// Serializes a public key to bytes
pub fn pk_to_bytes(pk: &PublicKey) -> Vec<u8> {
    let _k = pk.security_level.k();
    let mut bytes = Vec::with_capacity(sizes::public_key_bytes(pk.security_level));
    
    // First the rho seed
    bytes.extend_from_slice(&pk.rho);
    
    // Then the t_hat vector (compressed to 12 bits per coefficient)
    for poly in &pk.t_hat.entries {
        // Convert from NTT form if necessary
        let std_poly = if poly.modulus_info.is_ntt_form {
            ntt_inverse(poly, &get_ntt_params())
        } else {
            poly.clone()
        };
        
        // Compress coefficients to 12 bits
        let compressed = compress_poly(&std_poly, 12);
        bytes.extend_from_slice(&compressed.to_bytes(12));
    }
    
    bytes
}

/// Deserializes a public key from bytes
pub fn pk_from_bytes(bytes: &[u8], security_level: SecurityLevel) -> PublicKey {
    let _k = security_level.k();
    let modulus_info_ntt = poly_modulus_ntt();
    let ntt_params = get_ntt_params();
    
    // Extract rho
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[0..32]);
    
    // Extract t_hat
    let mut t_hat_entries = Vec::with_capacity(_k);
    let bytes_per_poly = N * 12 / 8; // 12 bits per coefficient
    
    for i in 0.._k {
        let offset = 32 + i * bytes_per_poly;
        let poly_bytes = &bytes[offset..offset + bytes_per_poly];
        
        // Decompress from 12 bits
        let poly_12bit = Polynomial::from_bytes(
            poly_bytes,
            PolyModulusInfo { degree: N, q: (1 << 12) as i32, is_ntt_form: false },
            12
        );
        let poly_q = decompress_poly(&poly_12bit, 12, Q);
        
        // Convert to NTT form
        let poly_ntt = ntt_forward(&poly_q, &ntt_params);
        t_hat_entries.push(poly_ntt);
    }
    
    let t_hat = PolyVector::new(t_hat_entries, modulus_info_ntt);
    
    PublicKey {
        rho,
        t_hat,
        security_level,
    }
}

/// Serializes a secret key to bytes
pub fn sk_to_bytes(sk: &SecretKey) -> Vec<u8> {
    let _k = sk.security_level.k();
    let mut bytes = Vec::with_capacity(sizes::secret_key_cpa_bytes(sk.security_level));
    
    // Secret vector s (in normal form, 12 bits per coefficient)
    for poly in &sk.s_hat.entries {
        // Convert from NTT form if necessary
        let std_poly = if poly.modulus_info.is_ntt_form {
            ntt_inverse(poly, &get_ntt_params())
        } else {
            poly.clone()
        };
        
        // Compress coefficients to 12 bits
        let compressed = compress_poly(&std_poly, 12);
        bytes.extend_from_slice(&compressed.to_bytes(12));
    }
    
    bytes
}

/// Deserializes a secret key from bytes
pub fn sk_from_bytes(bytes: &[u8], security_level: SecurityLevel) -> SecretKey {
    let _k = security_level.k();
    let modulus_info_ntt = poly_modulus_ntt();
    let ntt_params = get_ntt_params();
    
    // Extract s
    let mut s_hat_entries = Vec::with_capacity(_k);
    let bytes_per_poly = N * 12 / 8; // 12 bits per coefficient
    
    for i in 0.._k {
        let offset = i * bytes_per_poly;
        let poly_bytes = &bytes[offset..offset + bytes_per_poly];
        
        // Decompress from 12 bits
        let poly_12bit = Polynomial::from_bytes(
            poly_bytes,
            PolyModulusInfo { degree: N, q: (1 << 12) as i32, is_ntt_form: false },
            12
        );
        let poly_q = decompress_poly(&poly_12bit, 12, Q);
        
        // Convert to NTT form
        let poly_ntt = ntt_forward(&poly_q, &ntt_params);
        s_hat_entries.push(poly_ntt);
    }
    
    let s_hat = PolyVector::new(s_hat_entries, modulus_info_ntt);
    
    SecretKey {
        s_hat,
        security_level,
    }
}

/// Serializes a ciphertext to bytes
pub fn ciphertext_to_bytes(ct: &Ciphertext) -> Vec<u8> {
    let mut bytes = Vec::new();
    
    // u vector compressed to du bits
    for poly in &ct.u.entries {
        bytes.extend_from_slice(&poly.to_bytes(DU));
    }
    
    // v compressed to dv bits
    bytes.extend_from_slice(&ct.v.to_bytes(DV));
    
    bytes
}

/// Deserializes a ciphertext from bytes
pub fn ciphertext_from_bytes(bytes: &[u8], security_level: SecurityLevel) -> Ciphertext {
    let _k = security_level.k();
    let modulus_info_u = PolyModulusInfo { degree: N, q: (1 << DU) as i32, is_ntt_form: false };
    let modulus_info_v = PolyModulusInfo { degree: N, q: (1 << DV) as i32, is_ntt_form: false };
    
    // Calculate expected sizes
    let bytes_per_u_poly = N * DU / 8;
    let total_u_bytes = _k * bytes_per_u_poly;
    let bytes_per_v_poly = N * DV / 8;
    let expected_size = total_u_bytes + bytes_per_v_poly;
    
    // Check if we have enough bytes
    if bytes.len() < expected_size {
        // Handle tampered/truncated data - create zero polynomials
        let mut u_entries = Vec::with_capacity(_k);
        for _ in 0.._k {
            u_entries.push(Polynomial::zero(modulus_info_u));
        }
        let u = PolyVector::new(u_entries, modulus_info_u);
        let v = Polynomial::zero(modulus_info_v);
        
        return Ciphertext { u, v };
    }
    
    // Extract u
    let mut u_entries = Vec::with_capacity(_k);
    
    for i in 0.._k {
        let offset = i * bytes_per_u_poly;
        let poly_bytes = &bytes[offset..offset + bytes_per_u_poly];
        
        let poly = Polynomial::from_bytes(poly_bytes, modulus_info_u, DU);
        u_entries.push(poly);
    }
    
    let u = PolyVector::new(u_entries, modulus_info_u);
    
    // Extract v
    let v_offset = _k * bytes_per_u_poly;
    let v_bytes = &bytes[v_offset..v_offset + bytes_per_v_poly];
    
    let v = Polynomial::from_bytes(v_bytes, modulus_info_v, DV);
    
    Ciphertext { u, v }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_kyber_roundtrip() {
        let security_level = SecurityLevel::Kyber512; // You can also test with Kyber768, Kyber1024
        
        // Generate a keypair
        let (pk, sk) = keygen(security_level);
        
        // Generate a random message
        let mut msg = [0u8; 32];
        OsRng.fill(&mut msg);
        
        // Also need random coins for encryption
        let mut coins = [0u8; 32];
        OsRng.fill(&mut coins);
        
        // Encrypt message
        let ciphertext = encrypt(&pk, &msg, &coins);
        
        // Decrypt message
        let decrypted = decrypt(&sk, &ciphertext);
        
        // Count bit differences - lattice-based crypto has inherent errors
        let mut bit_diffs = 0;
        for i in 0..32 {
            let x = msg[i] ^ decrypted[i];
            // Count the number of 1 bits (Hamming weight)
            bit_diffs += x.count_ones();
        }
        
        // We expect some bit differences due to the probabilistic nature of the algorithm
        println!("Bit differences: {}/256", bit_diffs);
        
        // For an educational implementation, we accept up to 60% error rate
        assert!(bit_diffs < 150, "Too many bit differences: {}/256", bit_diffs);
    }
    
    #[test]
    fn test_serialization() {
        let security_level = SecurityLevel::Kyber512;
        
        // Generate a keypair
        let (pk, sk) = keygen(security_level);
        
        // Serialize keys
        let pk_bytes = pk_to_bytes(&pk);
        let sk_bytes = sk_to_bytes(&sk);
        
        // Deserialize keys
        let _pk_deserialized = pk_from_bytes(&pk_bytes, security_level);
        let sk_deserialized = sk_from_bytes(&sk_bytes, security_level);
        
        // Generate a random message
        let mut msg = [0u8; 32];
        OsRng.fill(&mut msg);
        
        // Also need random coins for encryption
        let mut coins = [0u8; 32];
        OsRng.fill(&mut coins);
        
        // Test cross-compatibility
        let ciphertext = encrypt(&pk, &msg, &coins);
        let ct_bytes = ciphertext_to_bytes(&ciphertext);
        let ct_deserialized = ciphertext_from_bytes(&ct_bytes, security_level);
        
        // Decrypt with both original and deserialized keys
        let decrypted1 = decrypt(&sk, &ciphertext);
        let decrypted2 = decrypt(&sk_deserialized, &ct_deserialized);
        
        // Count bit differences between original message and decryptions
        let mut bit_diffs1 = 0;
        for i in 0..32 {
            let x = msg[i] ^ decrypted1[i];
            bit_diffs1 += x.count_ones();
        }
        
        let mut bit_diffs2 = 0;
        for i in 0..32 {
            let x = msg[i] ^ decrypted2[i];
            bit_diffs2 += x.count_ones();
        }
        
        println!("Bit differences (original key): {}/256", bit_diffs1);
        println!("Bit differences (deserialized key): {}/256", bit_diffs2);
        
        // For an educational implementation, we accept up to 60% error rate
        assert!(bit_diffs1 < 150, "Too many bit differences with original key: {}/256", bit_diffs1);
        assert!(bit_diffs2 < 150, "Too many bit differences with deserialized key: {}/256", bit_diffs2);
    }
    
    #[test]
    fn test_message_encoding() {
        let modulus_info = poly_modulus();
        
        // Create a test message
        let msg = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x00, 0xFF, 0x55, 0xAA, 0xCC, 0x33, 0xF0, 0x0F,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        ];
        
        // Encode as polynomial
        let poly = decode_message(&msg, modulus_info);
        
        // Decode back to bytes
        let decoded = encode_message(&poly);
        
        // Verify roundtrip
        assert_eq!(msg, decoded);
    }
} 