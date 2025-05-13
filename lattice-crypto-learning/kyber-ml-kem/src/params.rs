use lattice_core::params::{PolyModulusInfo, kyber};

// Common Kyber parameters
pub const Q: i32 = kyber::Q;
pub const N: usize = kyber::N;
pub const DU: usize = kyber::DU;
pub const DV: usize = kyber::DV;

/// Represents the security parameter sets for Kyber/ML-KEM
#[derive(Debug, Clone, Copy)]
pub enum SecurityLevel {
    /// Kyber-512 (ML-KEM 512)
    Kyber512,
    /// Kyber-768 (ML-KEM 768)
    Kyber768,
    /// Kyber-1024 (ML-KEM 1024)
    Kyber1024,
}

impl SecurityLevel {
    /// Returns the module rank k based on security level
    pub fn k(&self) -> usize {
        match self {
            SecurityLevel::Kyber512 => 2,
            SecurityLevel::Kyber768 => 3,
            SecurityLevel::Kyber1024 => 4,
        }
    }
    
    /// Returns the noise parameter eta1 based on security level
    pub fn eta1(&self) -> usize {
        match self {
            SecurityLevel::Kyber512 => 3,
            SecurityLevel::Kyber768 => 2,
            SecurityLevel::Kyber1024 => 2,
        }
    }
    
    /// Returns the noise parameter eta2 based on security level
    pub fn eta2(&self) -> usize {
        match self {
            SecurityLevel::Kyber512 => 2,
            SecurityLevel::Kyber768 => 2,
            SecurityLevel::Kyber1024 => 2,
        }
    }
    
    /// Returns the internal lattice parameters
    pub fn lattice_params(&self) -> lattice_core::params::LatticeParams {
        match self {
            SecurityLevel::Kyber512 => kyber::kyber_512(),
            SecurityLevel::Kyber768 => kyber::kyber_768(),
            SecurityLevel::Kyber1024 => kyber::kyber_1024(),
        }
    }
}

/// Creates the polynomial modulus info for Kyber
pub fn poly_modulus() -> PolyModulusInfo {
    PolyModulusInfo {
        degree: N,
        q: Q,
        is_ntt_form: false,
    }
}

/// Creates the polynomial modulus info for NTT domain
pub fn poly_modulus_ntt() -> PolyModulusInfo {
    PolyModulusInfo {
        degree: N,
        q: Q,
        is_ntt_form: true,
    }
}

/// Key sizes in bytes
pub mod sizes {
    use super::SecurityLevel;
    
    /// Seed size in bytes
    pub const SEED_BYTES: usize = 32;
    /// Share secret size in bytes
    pub const SHARED_SECRET_BYTES: usize = 32;
    /// Message size in bytes (for encapsulation)
    pub const MESSAGE_BYTES: usize = 32;
    
    /// Calculate public key size based on security level
    pub fn public_key_bytes(level: SecurityLevel) -> usize {
        let _k = level.k();
        SEED_BYTES + _k * super::N * 12 / 8  // rho + t (12 bits per coefficient)
    }
    
    /// Calculate secret key size based on security level (for CPA)
    pub fn secret_key_cpa_bytes(level: SecurityLevel) -> usize {
        let _k = level.k();
        _k * super::N * 12 / 8  // s (12 bits per coefficient)
    }
    
    /// Calculate secret key size based on security level (for CCA-KEM)
    pub fn secret_key_kem_bytes(level: SecurityLevel) -> usize {
        let _k = level.k();
        secret_key_cpa_bytes(level) + // s
        public_key_bytes(level) +     // pk
        SEED_BYTES +                  // hash of pk
        SEED_BYTES                    // random z
    }
    
    /// Calculate ciphertext size based on security level
    pub fn ciphertext_bytes(level: SecurityLevel) -> usize {
        let _k = level.k();
        _k * super::N * super::DU / 8 + // u (du bits per coefficient)
        super::N * super::DV / 8       // v (dv bits per coefficient)
    }
} 