use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use sha3::Digest;

/// Provides a SHAKE-128 hash of the given data
pub fn shake128(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, data);
    let mut reader = hasher.finalize_xof();
    
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    
    output
}

/// Provides a SHAKE-256 hash of the given data
pub fn shake256(data: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, data);
    let mut reader = hasher.finalize_xof();
    
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    
    output
}

/// Provides a SHA3-256 hash of the given data
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, data);
    
    hasher.finalize().into()
}

/// Provides a SHA3-512 hash of the given data
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, data);
    
    hasher.finalize().into()
}

/// Implements PRF(seed, nonce, len) function used in various schemes
pub fn prf(seed: &[u8], nonce: u16, len: usize) -> Vec<u8> {
    let mut input = seed.to_vec();
    
    // Append nonce in little-endian format
    let nonce_bytes = nonce.to_le_bytes();
    input.extend_from_slice(&nonce_bytes);
    
    // Use SHAKE-256 to generate output
    shake256(&input, len)
}

/// Hash function G used in the Fujisaki-Okamoto transform (Figure 4)
pub fn hash_g(m: &[u8], h_pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut data = Vec::with_capacity(m.len() + h_pk.len());
    data.extend_from_slice(m);
    data.extend_from_slice(h_pk);
    
    let hash = shake256(&data, 64); // Can adjust length as needed
    
    // Split the hash into two parts for K and r_coins
    let (k, r_coins) = hash.split_at(32);
    
    (k.to_vec(), r_coins.to_vec())
}

/// Hash function H used in various locations (Figures 4, 10)
pub fn hash_h(data: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    
    for chunk in data {
        Digest::update(&mut hasher, chunk);
    }
    
    let result = hasher.finalize();
    result.to_vec()
}

/// Combines multiple byte arrays for hashing
pub fn concat_for_hash(arrays: &[&[u8]]) -> Vec<u8> {
    let total_len = arrays.iter().map(|a| a.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    
    for arr in arrays {
        result.extend_from_slice(arr);
    }
    
    result
}

/// Generate a random nonce and bytes using seed
pub fn generate_randomness(seed: &[u8], nonce: u16, output_len: usize) -> Vec<u8> {
    prf(seed, nonce, output_len)
}

/// Hash function for commitments in Fiat-Shamir
pub fn hash_for_fiat_shamir(data: &[&[u8]]) -> Vec<u8> {
    hash_h(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    
    #[test]
    fn test_shake128() {
        let data = b"test data";
        let hash1 = shake128(data, 32);
        let hash2 = shake128(data, 32);
        
        // Same input should give same output
        assert_eq!(hash1, hash2);
        
        // Different output lengths
        let hash3 = shake128(data, 64);
        assert_eq!(hash3[..32], hash1);
    }
    
    #[test]
    fn test_shake256() {
        let data = b"test data";
        let hash1 = shake256(data, 32);
        let hash2 = shake256(data, 32);
        
        // Same input should give same output
        assert_eq!(hash1, hash2);
        
        // Different output lengths
        let hash3 = shake256(data, 64);
        assert_eq!(hash3[..32], hash1);
    }
    
    #[test]
    fn test_sha3_256() {
        let data = b"test data";
        let hash1 = sha3_256(data);
        let hash2 = sha3_256(data);
        
        // Same input should give same output
        assert_eq!(hash1, hash2);
        
        // Verify against a known SHA3-256 hash
        let expected = hex::decode("7d97362108ce4a7da11ec5a4dc6437bef83a9e6a36dddd78d85d8fbc55445e83").unwrap();
        assert_eq!(hash1, expected.as_slice());
    }
    
    #[test]
    fn test_prf() {
        let seed = b"test seed";
        let nonce1 = 1u16;
        let nonce2 = 2u16;
        
        let out1 = prf(seed, nonce1, 32);
        let out2 = prf(seed, nonce1, 32);
        let out3 = prf(seed, nonce2, 32);
        
        // Same seed/nonce should give same output
        assert_eq!(out1, out2);
        
        // Different nonce should give different output
        assert_ne!(out1, out3);
    }
    
    #[test]
    fn test_hash_g() {
        let m = b"message";
        let h_pk = b"public key hash";
        
        let (k1, r1) = hash_g(m, h_pk);
        let (k2, r2) = hash_g(m, h_pk);
        
        // Same input should give same output
        assert_eq!(k1, k2);
        assert_eq!(r1, r2);
        
        // Different length outputs
        assert_eq!(k1.len(), 32);
        assert_eq!(r1.len(), 32);
    }
    
    #[test]
    fn test_hash_h() {
        let data1 = b"first part";
        let data2 = b"second part";
        
        let hash1 = hash_h(&[data1, data2]);
        let hash2 = hash_h(&[data1, data2]);
        
        // Same input should give same output
        assert_eq!(hash1, hash2);
        
        // Hash bytes concatenated together
        let concatenated = concat_for_hash(&[data1, data2]);
        let hash3 = hash_h(&[&concatenated]);
        
        // Should be different (hash(a|b) != hash([a,b]))
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_concat_for_hash() {
        let data1 = b"first part";
        let data2 = b"second part";
        
        let concatenated = concat_for_hash(&[data1, data2]);
        
        // Verify concatenation
        let mut expected = Vec::new();
        expected.extend_from_slice(data1);
        expected.extend_from_slice(data2);
        
        assert_eq!(concatenated, expected);
    }
} 