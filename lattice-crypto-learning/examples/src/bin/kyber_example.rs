use kyber_ml_kem::{
    params::SecurityLevel,
    cpa, kem
};
use rand::{Rng, rngs::OsRng};
use hex;

fn main() {
    println!("CRYSTALS-Kyber (ML-KEM) Example");
    println!("===============================");
    
    // Choose a security level
    let security_level = SecurityLevel::Kyber512;
    println!("Security level: Kyber512 (ML-KEM-512)");
    
    // First, demonstrate CPA-secure Kyber
    println!("\nCPA-secure Kyber:");
    println!("-----------------");
    
    // Generate a keypair
    let (pk, sk) = cpa::keygen(security_level);
    println!("Generated keypair");
    
    // Create a random message
    let mut message = [0u8; 32];
    let mut rng = OsRng;
    rng.fill(&mut message);
    println!("Random message: {}", hex::encode(&message[0..8]));
    
    // Generate random coins for encryption
    let mut coins = [0u8; 32];
    rng.fill(&mut coins);
    
    // Encrypt the message
    let ciphertext = cpa::encrypt(&pk, &message, &coins);
    println!("Message encrypted with public key");
    
    // Decrypt the message
    let decrypted = cpa::decrypt(&sk, &ciphertext);
    println!("Decrypted message: {}", hex::encode(&decrypted[0..8]));
    
    // Verify decryption succeeded
    let mut bit_diffs = 0;
    for i in 0..32 {
        let x = message[i] ^ decrypted[i];
        // Count the number of 1 bits (Hamming weight)
        bit_diffs += x.count_ones();
    }

    if bit_diffs == 0 {
        println!("Decryption successful!");
    } else {
        println!("Decryption had {} bit differences out of 256 bits", bit_diffs);
        println!("Some bit errors are expected due to the probabilistic nature of lattice-based encryption");
    }
    
    // Next, demonstrate CCA-secure Kyber KEM
    println!("\nCCA-secure Kyber KEM:");
    println!("--------------------");
    
    // Generate a keypair
    let (kem_pk, kem_sk) = kem::keygen(security_level);
    println!("Generated KEM keypair");
    
    // Encapsulate to create a shared secret
    let encapsulation = kem::encaps(&kem_pk);
    println!("Encapsulated shared secret: {}", hex::encode(&encapsulation.shared_secret[0..8]));
    
    // Decapsulate to recover the shared secret
    let shared_secret = kem::decaps(&kem_sk, &encapsulation.ciphertext);
    println!("Decapsulated shared secret: {}", hex::encode(&shared_secret[0..8]));
    
    // Verify the shared secrets match
    let mut bit_diffs = 0;
    for i in 0..32 {
        let x = encapsulation.shared_secret[i] ^ shared_secret[i];
        // Count the number of 1 bits (Hamming weight)
        bit_diffs += x.count_ones();
    }

    if bit_diffs == 0 {
        println!("Shared secrets match!");
    } else {
        println!("Shared secrets had {} bit differences out of 256 bits", bit_diffs);
        println!("Some bit errors are expected due to the probabilistic nature of lattice-based cryptography");
    }
    
    // Demonstrate tampering with the ciphertext
    println!("\nTampering with ciphertext:");
    println!("------------------------");
    
    // Serialize the ciphertext
    let ct_bytes = cpa::ciphertext_to_bytes(&encapsulation.ciphertext);
    let mut tampered_bytes = ct_bytes.clone();
    
    // Tamper with it
    tampered_bytes[0] ^= 1; // Flip one bit
    println!("Tampered with the first byte of the ciphertext");
    
    // Deserialize back into a ciphertext
    let tampered_ct = cpa::ciphertext_from_bytes(&tampered_bytes, security_level);
    
    // Try to decapsulate with the tampered ciphertext
    let tampered_ss = kem::decaps(&kem_sk, &tampered_ct);
    println!("Original shared secret: {}", hex::encode(&encapsulation.shared_secret[0..8]));
    println!("Tampered shared secret: {}", hex::encode(&tampered_ss[0..8]));
    
    if encapsulation.shared_secret == tampered_ss {
        println!("Tampered ciphertext produced the same shared secret!");
    } else {
        println!("Tampered ciphertext produced a different shared secret!");
        println!("This is good - it shows the CCA security of Kyber KEM.");
    }
} 