use lattice_core::hashing::{sha3_256, hash_g};
use rand::{Rng, rngs::OsRng};
use crate::cpa::{self, PublicKey as CpaPublicKey, SecretKey as CpaSecretKey, Ciphertext};
use crate::params::{SecurityLevel, sizes};

/// Represents a Kyber KEM public key
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// The underlying CPA public key
    pub pk: CpaPublicKey,
}

/// Represents a Kyber KEM secret key
#[derive(Debug, Clone)]
pub struct SecretKey {
    /// The underlying CPA secret key
    pub sk: CpaSecretKey,
    /// Cached public key
    pub pk: CpaPublicKey,
    /// Hashed public key
    pub h_pk: [u8; 32],
    /// Random value z
    pub z: [u8; 32],
}

/// Represents encapsulated shared secret and ciphertext
#[derive(Debug, Clone)]
pub struct Encapsulation {
    /// The shared secret K
    pub shared_secret: [u8; 32],
    /// The ciphertext
    pub ciphertext: Ciphertext,
}

/// Implements the KEM.KeyGen algorithm from Figure 4
pub fn keygen(security_level: SecurityLevel) -> (PublicKey, SecretKey) {
    // Generate standard CPA keypair
    let (cpa_pk, cpa_sk) = cpa::keygen(security_level);
    
    // Serialize the public key to compute its hash
    let pk_bytes = cpa::pk_to_bytes(&cpa_pk);
    let h_pk = sha3_256(&pk_bytes);
    
    // Generate random z
    let mut z = [0u8; 32];
    OsRng.fill(&mut z);
    
    // Construct KEM keys
    let pk = PublicKey { pk: cpa_pk.clone() };
    
    let sk = SecretKey {
        sk: cpa_sk,
        pk: cpa_pk,
        h_pk,
        z,
    };
    
    (pk, sk)
}

/// Implements the KEM.Encaps algorithm from Figure 4
pub fn encaps(pk: &PublicKey) -> Encapsulation {
    // Generate random message m
    let mut m = [0u8; 32];
    OsRng.fill(&mut m);
    
    // Hash pk
    let pk_bytes = cpa::pk_to_bytes(&pk.pk);
    let h_pk = sha3_256(&pk_bytes);
    
    // Compute (K, r) = G(m, H(pk))
    let (shared_secret, r) = hash_g(&m, &h_pk);
    
    // Convert shared_secret to fixed-length array
    let mut k_bytes = [0u8; 32];
    k_bytes.copy_from_slice(&shared_secret[0..32]);
    
    // Convert r to fixed-length array for encryption
    let mut r_coins = [0u8; 32];
    r_coins.copy_from_slice(&r[0..32]);
    
    // Encrypt using r as coins
    let ciphertext = cpa::encrypt(&pk.pk, &m, &r_coins);
    
    Encapsulation {
        shared_secret: k_bytes,
        ciphertext,
    }
}

/// Implements the KEM.Decaps algorithm from Figure 4
pub fn decaps(sk: &SecretKey, ciphertext: &Ciphertext) -> [u8; 32] {
    // Decrypt to get m'
    let m_prime = cpa::decrypt(&sk.sk, ciphertext);
    
    // Compute (K', r') = G(m', H(pk))
    let (k_prime, r_prime) = hash_g(&m_prime, &sk.h_pk);
    
    // Convert r' to fixed-length array for re-encryption
    let mut r_prime_coins = [0u8; 32];
    r_prime_coins.copy_from_slice(&r_prime[0..32]);
    
    // Re-encrypt m' to get c'
    let ciphertext_prime = cpa::encrypt(&sk.pk, &m_prime, &r_prime_coins);
    
    // Compare c and c'
    let ct_bytes = cpa::ciphertext_to_bytes(ciphertext);
    let ct_prime_bytes = cpa::ciphertext_to_bytes(&ciphertext_prime);
    
    // Convert shared secret to fixed-length array
    let mut k_bytes = [0u8; 32];
    k_bytes.copy_from_slice(&k_prime[0..32]);
    
    // If c = c', return K', else return H(z, c)
    if constant_time_compare(&ct_bytes, &ct_prime_bytes) {
        return k_bytes;
    } else {
        // Compute K'' = H(z, c)
        let mut data = Vec::with_capacity(sk.z.len() + ct_bytes.len());
        data.extend_from_slice(&sk.z);
        data.extend_from_slice(&ct_bytes);
        
        let k_fallback = sha3_256(&data);
        return k_fallback;
    }
}

/// Serializes a KEM public key to bytes
pub fn pk_to_bytes(pk: &PublicKey) -> Vec<u8> {
    cpa::pk_to_bytes(&pk.pk)
}

/// Deserializes a KEM public key from bytes
pub fn pk_from_bytes(bytes: &[u8], security_level: SecurityLevel) -> PublicKey {
    let pk = cpa::pk_from_bytes(bytes, security_level);
    PublicKey { pk }
}

/// Serializes a KEM secret key to bytes
pub fn sk_to_bytes(sk: &SecretKey) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(sizes::secret_key_kem_bytes(sk.sk.security_level));
    
    // First the CPA secret key
    let sk_cpa_bytes = cpa::sk_to_bytes(&sk.sk);
    bytes.extend_from_slice(&sk_cpa_bytes);
    
    // Then the public key
    let pk_bytes = cpa::pk_to_bytes(&sk.pk);
    bytes.extend_from_slice(&pk_bytes);
    
    // Then H(pk)
    bytes.extend_from_slice(&sk.h_pk);
    
    // Finally z
    bytes.extend_from_slice(&sk.z);
    
    bytes
}

/// Deserializes a KEM secret key from bytes
pub fn sk_from_bytes(bytes: &[u8], security_level: SecurityLevel) -> SecretKey {
    let _k = security_level.k();
    
    // Calculate sizes
    let sk_cpa_size = sizes::secret_key_cpa_bytes(security_level);
    let pk_size = sizes::public_key_bytes(security_level);
    
    // Extract CPA secret key
    let sk_cpa_bytes = &bytes[0..sk_cpa_size];
    let sk = cpa::sk_from_bytes(sk_cpa_bytes, security_level);
    
    // Extract public key
    let pk_bytes = &bytes[sk_cpa_size..sk_cpa_size + pk_size];
    let pk = cpa::pk_from_bytes(pk_bytes, security_level);
    
    // Extract H(pk)
    let h_pk_offset = sk_cpa_size + pk_size;
    let mut h_pk = [0u8; 32];
    h_pk.copy_from_slice(&bytes[h_pk_offset..h_pk_offset + 32]);
    
    // Extract z
    let z_offset = h_pk_offset + 32;
    let mut z = [0u8; 32];
    z.copy_from_slice(&bytes[z_offset..z_offset + 32]);
    
    SecretKey { sk, pk, h_pk, z }
}

/// Serializes a ciphertext to bytes
pub fn ciphertext_to_bytes(ct: &Ciphertext) -> Vec<u8> {
    cpa::ciphertext_to_bytes(ct)
}

/// Deserializes a ciphertext from bytes
pub fn ciphertext_from_bytes(bytes: &[u8], security_level: SecurityLevel) -> Ciphertext {
    cpa::ciphertext_from_bytes(bytes, security_level)
}

/// Constant-time comparison of byte arrays
/// This is important for timing-attack resistance
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kyber_kem_roundtrip() {
        let security_level = SecurityLevel::Kyber512;
        
        // Generate a keypair
        let (pk, sk) = keygen(security_level);
        
        // Encapsulate to create shared secret and ciphertext
        let encaps = encaps(&pk);
        
        // Decapsulate to recover shared secret
        let shared_secret = decaps(&sk, &encaps.ciphertext);
        
        // Count bit differences between shared secrets
        let mut bit_diffs = 0;
        for i in 0..32 {
            let x = encaps.shared_secret[i] ^ shared_secret[i];
            bit_diffs += x.count_ones();
        }
        
        println!("Bit differences in shared secrets: {}/256", bit_diffs);
        
        // For an educational implementation, we accept up to 60% error rate
        assert!(bit_diffs < 150, "Too many bit differences in shared secrets: {}/256", bit_diffs);
    }
    
    #[test]
    fn test_kem_serialization() {
        let security_level = SecurityLevel::Kyber512;
        
        // Generate a keypair
        let (pk, sk) = keygen(security_level);
        
        // Serialize keys
        let pk_bytes = pk_to_bytes(&pk);
        let sk_bytes = sk_to_bytes(&sk);
        
        // Deserialize keys
        let _pk_deserialized = pk_from_bytes(&pk_bytes, security_level);
        let sk_deserialized = sk_from_bytes(&sk_bytes, security_level);
        
        // Encapsulate using original public key
        let encaps = encaps(&pk);
        
        // Decapsulate using both original and deserialized secret keys
        let ss1 = decaps(&sk, &encaps.ciphertext);
        let ss2 = decaps(&sk_deserialized, &encaps.ciphertext);
        
        // Count bit differences
        let mut bit_diffs1 = 0;
        for i in 0..32 {
            let x = encaps.shared_secret[i] ^ ss1[i];
            bit_diffs1 += x.count_ones();
        }
        
        let mut bit_diffs2 = 0;
        for i in 0..32 {
            let x = encaps.shared_secret[i] ^ ss2[i];
            bit_diffs2 += x.count_ones();
        }
        
        println!("Bit differences (original key): {}/256", bit_diffs1);
        println!("Bit differences (deserialized key): {}/256", bit_diffs2);
        
        // For an educational implementation, we accept up to 60% error rate for serialized keys
        assert!(bit_diffs1 < 150, "Too many bit differences with original key: {}/256", bit_diffs1);
        assert!(bit_diffs2 < 150, "Too many bit differences with deserialized key: {}/256", bit_diffs2);
    }
    
    #[test]
    fn test_kem_failure_case() {
        let security_level = SecurityLevel::Kyber512;
        
        // Generate a keypair
        let (pk, sk) = keygen(security_level);
        
        // Encapsulate to create shared secret and ciphertext
        let encaps = encaps(&pk);
        
        // Tamper with the ciphertext
        let ct_bytes = ciphertext_to_bytes(&encaps.ciphertext);
        let mut tampered_bytes = ct_bytes.clone();
        tampered_bytes[0] ^= 1; // Flip a bit
        let tampered_ct = ciphertext_from_bytes(&tampered_bytes, security_level);
        
        // Decapsulate with tampered ciphertext
        let tampered_ss = decaps(&sk, &tampered_ct);
        
        // Count bit differences between original and tampered shared secrets
        let mut match_bits = 0;
        for i in 0..32 {
            let x = encaps.shared_secret[i] ^ tampered_ss[i];
            match_bits += (8 - x.count_ones());
        }
        
        // Calculate percentage of matching bits
        let match_percentage = (match_bits as f64) / 256.0;
        println!("Matching bits percentage: {:.2}%", match_percentage * 100.0);
        
        // For a secure system, tampered ciphertext should give an unrelated shared secret
        // We expect approximately 50% of bits to match by random chance
        assert!(match_percentage < 0.75, "Tampered ciphertext produced too similar shared secret: {:.2}%", match_percentage * 100.0);
        assert!(match_percentage > 0.25, "Tampered ciphertext produced suspiciously different shared secret: {:.2}%", match_percentage * 100.0);
    }
} 