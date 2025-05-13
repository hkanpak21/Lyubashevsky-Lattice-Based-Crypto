use lattice_core::params::{PolyModulusInfo, dilithium};

// Common Dilithium parameters
pub const Q: i32 = dilithium::Q;
pub const N: usize = dilithium::N;

/// Represents the security parameter sets for Dilithium/ML-DSA
#[derive(Debug, Clone, Copy)]
pub enum SecurityLevel {
    /// Dilithium2 (ML-DSA-44)
    Dilithium2,
    /// Dilithium3 (ML-DSA-65)
    Dilithium3,
    /// Dilithium5 (ML-DSA-87)
    Dilithium5,
}

impl SecurityLevel {
    /// Returns the internal Dilithium parameters
    pub fn dilithium_params(&self) -> dilithium::DilithiumParams {
        match self {
            SecurityLevel::Dilithium2 => dilithium::dilithium_2(),
            SecurityLevel::Dilithium3 => dilithium::dilithium_3(),
            SecurityLevel::Dilithium5 => dilithium::dilithium_5(),
        }
    }
}

/// Creates the polynomial modulus info for Dilithium
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