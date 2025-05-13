/// Represents the modulus polynomial f(X) = X^n + 1 for the ring R_q
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolyModulusInfo {
    /// Degree of the polynomial modulus (n)
    pub degree: usize,
    /// Coefficient modulus (q)
    pub q: i32,
    /// Indicates if the polynomial is in NTT form
    pub is_ntt_form: bool,
}

/// Represents common parameter sets for lattice cryptography schemes
#[derive(Debug, Clone)]
pub struct LatticeParams {
    /// Modulus for the ring Z_q
    pub q: i32,
    /// Polynomial modulus degree (generally a power of 2)
    pub n: usize,
    /// Error distribution parameter
    pub eta: usize,
    /// Beta bound for sampling
    pub beta: i32,
    /// Matrix dimension parameter (k for Kyber, different meaning for Dilithium)
    pub k: usize,
}

// Predefined Kyber parameter sets from Table 3
pub mod kyber {
    use super::*;

    /// Kyber common parameters
    pub const Q: i32 = 3329;
    pub const N: usize = 256; // Degree of polynomial X^n + 1
    pub const DU: usize = 10; // Compression parameter for ciphertext u
    pub const DV: usize = 4;  // Compression parameter for ciphertext v
    
    /// Kyber-512 parameters (k=2, η1=3, η2=2)
    pub fn kyber_512() -> LatticeParams {
        LatticeParams {
            q: Q,
            n: N,
            eta: 3,   // η1 for noise polynomial
            beta: 2,   // η2 in the paper
            k: 2,      // Module rank
        }
    }

    /// Kyber-768 parameters (k=3, η1=2, η2=2)
    pub fn kyber_768() -> LatticeParams {
        LatticeParams {
            q: Q,
            n: N,
            eta: 2,    // η1
            beta: 2,    // η2
            k: 3,       // Module rank
        }
    }

    /// Kyber-1024 parameters (k=4, η1=2, η2=2)
    pub fn kyber_1024() -> LatticeParams {
        LatticeParams {
            q: Q,
            n: N,
            eta: 2,    // η1
            beta: 2,    // η2
            k: 4,       // Module rank
        }
    }
}

// Predefined Dilithium parameter sets from Table 4 or similar
pub mod dilithium {
    use super::*;

    /// Dilithium common parameters
    pub const Q: i32 = 8380417; // 2^23 - 2^13 + 1
    pub const N: usize = 256;   // Degree of polynomial X^n + 1
    
    /// Represents Dilithium-specific parameters
    #[derive(Debug, Clone)]
    pub struct DilithiumParams {
        /// Base lattice parameters
        pub base: LatticeParams,
        /// Module dimension l
        pub l: usize,
        /// Bound for signature γ1
        pub gamma1: i32,
        /// Bound for compression γ2 (2^γ2)
        pub gamma2: i32,
        /// Rejection parameter β = τη
        pub beta: i32,
        /// Challenge space parameter τ
        pub tau: usize,
        /// Number of 1's in challenge polynomial
        pub omega: usize,
    }

    /// Dilithium-2 parameters from Table 4
    pub fn dilithium_2() -> DilithiumParams {
        DilithiumParams {
            base: LatticeParams {
                q: Q,
                n: N,
                eta: 2,  // η for secret keys
                beta: 78, // τ * η = 39 * 2 = 78
                k: 4,     // Module dimension k
            },
            l: 4,
            gamma1: 131072,  // 2^17
            gamma2: 95,     // From eq (127)
            beta: 78,    // τ * η = 39 * 2 = 78
            tau: 39,
            omega: 80,
        }
    }
    
    /// Dilithium-3 parameters (higher security level)
    pub fn dilithium_3() -> DilithiumParams {
        DilithiumParams {
            base: LatticeParams {
                q: Q,
                n: N,
                eta: 4,
                beta: 196, // τ * η = 49 * 4 = 196
                k: 6,
            },
            l: 5,
            gamma1: 524288,  // 2^19
            gamma2: 261,
            beta: 196,   // τ * η = 49 * 4 = 196
            tau: 49,
            omega: 55,
        }
    }
    
    /// Dilithium-5 parameters (highest security level)
    pub fn dilithium_5() -> DilithiumParams {
        DilithiumParams {
            base: LatticeParams {
                q: Q,
                n: N,
                eta: 2,
                beta: 120, // τ * η = 60 * 2 = 120
                k: 8,
            },
            l: 7,
            gamma1: 524288,  // 2^19
            gamma2: 147,
            beta: 120,   // τ * η = 60 * 2 = 120
            tau: 60,
            omega: 75,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_params() {
        let k512 = kyber::kyber_512();
        assert_eq!(k512.q, 3329);
        assert_eq!(k512.n, 256);
        assert_eq!(k512.k, 2);
        assert_eq!(k512.eta, 3);
        
        let k1024 = kyber::kyber_1024();
        assert_eq!(k1024.k, 4);
    }

    #[test]
    fn test_dilithium_params() {
        let d2 = dilithium::dilithium_2();
        assert_eq!(d2.base.q, 8380417);
        assert_eq!(d2.base.n, 256);
        assert_eq!(d2.l, 4);
        assert_eq!(d2.base.k, 4);
        
        let d5 = dilithium::dilithium_5();
        assert_eq!(d5.base.k, 8);
        assert_eq!(d5.l, 7);
    }
} 