Okay, this is an excellent document for learning! Let's break this down.

Part 1: Extracted Functionalities with Functions
================================================

I'll interpret "functionalities with functions" as the core cryptographic algorithms and mathematical operations described.

**I. Basic LWE Encryption (Section 2)**

1.  **Key Generation (Sec 2.2, Eq 2; Sec 2.3.1, Eq 6)**
    *   `LWE_KeyGen_Basic(params) -> (sk, pk)`
        *   `sk`: secret key `s` (vector of small integers)
        *   `pk`: public key `(A, t = As + e1)` (matrix `A`, vector `t`)
        *   `params`: `m, n, q, β` (dimensions, modulus, noise bound)
2.  **Encryption (Sec 2.2, Eq 3; Sec 2.3.1, Eq 7)**
    *   `LWE_Encrypt_Basic(pk, μ) -> (u, v)`
        *   `μ`: message (e.g., a bit {0,1} or element in Zq)
        *   `(u,v)`: ciphertext (vector `u`, scalar/vector `v`)
        *   Involves random vector `r`, errors `e2, e3`.
3.  **Decryption (Sec 2.2, Eq 4; Sec 2.3.1, computation for Eq 9)**
    *   `LWE_Decrypt_Basic(sk, (u,v)) -> μ_recovered`
        *   Computes `v - uT s` (or `v - us` depending on convention)
        *   Recovers `μ` by checking proximity to 0 or `q/2` (for binary message).
4.  **Ciphertext/PK Compression/Decompression (Sec 2.5.1, 2.5.2)**
    *   `Compress(x, q, p) -> x_compressed` (maps element from Zq to Zp, Def 3: `[x]q->p`)
    *   `Decompress(x_compressed, q, p) -> x_decompressed` (maps element from Zp to Zq, `[[x_compressed]p->q]`)
    *   `HIGHS(v, S_params)` (Sec 2.5.1, 2.5.2 item 3)
    *   `LOWS(v, S_params)` (Sec 2.5.1, 2.5.2 item 4)
5.  **Non-Interactive Key Exchange (NIKE) (Sec 2.6)**
    *   `NIKE_Gen_Msg(A, params) -> (private_val, public_msg)`
        *   `private_val`: (si, ei)
        *   `public_msg`: ui = sTi A + eTi (or Asi + ei)
    *   `NIKE_Shared_Key(private_val_i, public_msg_j) -> shared_bit_or_key`
        *   e.g., `s1T u2` and check proximity to q/2.

**II. Hardness & Lattice Basics (Section 3)**
(These are more conceptual/problem definitions than functions to implement directly for schemes, but math building blocks)
1.  **Lattice Definition**
    *   `Generate_L_perp_A(A, q)`: Given matrix A, define the q-ary lattice L⊥(A). (Eq 29)
2.  **SIS Problem Oracle (Conceptual)**
    *   `Solve_SIS(A, q, β) -> (s1, s2)` such that As1+s2=0. (Def 4)
3.  **LWE Problem Oracle (Conceptual)**
    *   `Distinguish_LWE_vs_Uniform(sample) -> bool`. (Def 1, 2)

**III. Encryption over Polynomial Rings (Section 4)**

1.  **Polynomial Arithmetic (Sec 4.1)**
    *   `Poly_add(p1, p2, R_qf) -> p_sum`
    *   `Poly_mul(p1, p2, R_qf) -> p_prod` (involves reduction mod f, coefficients mod q)
    *   `Poly_scalar_mul(scalar, p, R_qf) -> p_scaled`
    *   `Poly_from_bytes(bytes), Poly_to_bytes(p)`
2.  **Number Theoretic Transform (NTT) (Sec 4.6)**
    *   `NTT(poly, params_qf) -> poly_ntt`
    *   `Inverse_NTT(poly_ntt, params_qf) -> poly`
    *   `NTT_componentwise_mul(poly1_ntt, poly2_ntt) -> prod_ntt`
3.  **Generalized LWE Encryption (Ring-LWE/Module-LWE) (Sec 4.3)**
    *   `RLWE_KeyGen(params_R_qf_k) -> (sk, pk)` (Eq 51, Fig 3 `CPA-KeyGen`)
        *   `sk`: vector of polynomials `s`
        *   `pk`: (matrix of polynomials `A`, vector of polynomials `t = As + e1`)
    *   `RLWE_Encrypt(pk, μ_poly) -> (u_vec_poly, v_poly)` (Eq 52, Fig 3 `CPA-Encrypt` core)
        *   `μ_poly`: message polynomial
    *   `RLWE_Decrypt(sk, (u_vec_poly, v_poly)) -> μ_poly_recovered` (Eq 54, Fig 3 `CPA-Decrypt` core)
4.  **NTRU Operations (Sec 4.4.1)**
    *   `NTRU_KeyGen(params_R_qf_p_beta) -> (pk_a, sk_g2)` (Eq 57)
    *   `NTRU_OWF(pk_a, s, e) -> b` (Eq 58)
    *   `NTRU_Invert(sk_g2, b, params_R_qf_p) -> (s_rec, e_rec)` (Eq 59, 60, 61)
5.  **CRYSTALS-Kyber (ML-KEM) (Sec 4.7, Fig 3)**
    *   `Kyber_CPA_KeyGen(params) -> (pk, sk)`
    *   `Kyber_CPA_Encrypt(pk, m_poly, randomness_params) -> ctxt_uv` (uses polynomial arithmetic, sampling from `ψη`, compression)
    *   `Kyber_CPA_Decrypt(sk, ctxt_uv) -> m_poly_recovered` (uses decompression)
6.  **CPA to CCA-KEM (Fujisaki-Okamoto) (Sec 4.8, Fig 4)**
    *   `KEM_KeyGen(CPA_KeyGen_func) -> (pk, sk)`
    *   `KEM_Encaps(pk, CPA_Encrypt_func, H_hash, G_hash) -> (shared_key, ctxt)`
    *   `KEM_Decaps(sk, ctxt, CPA_Decrypt_func, CPA_Encrypt_func, H_hash, G_hash) -> shared_key_or_fail`

**IV. Digital Signatures from Σ-Protocols (Section 5)**

1.  **Basic Σ-Protocol (Fiat-Shamir with Aborts style) (Fig 5)**
    *   `Sigma_Prover_P1(params) -> (y1, y2, w)` (Prover's first message)
    *   `Sigma_Verifier_Challenge(params_C) -> c` (Verifier sends challenge)
    *   `Sigma_Prover_P2(sk_s1_s2, y1, y2, c) -> (z1, z2)_or_⊥` (Prover's response, includes rejection sampling)
    *   `Sigma_Verifier_Verify(pk_A_t, w, c, z1, z2) -> bool`
2.  **Σ-Protocol with Reduced Proof Size (Fig 8)**
    *   `Sigma_Reduced_Prover_P1(params_S_ds) -> (y, w)`
    *   `Sigma_Reduced_Verifier_Challenge(params_C) -> c`
    *   `Sigma_Reduced_Prover_P2(sk_s1_s2, y, c, params_S_ds) -> z_or_⊥`
    *   `Sigma_Reduced_Verifier_Verify(pk_A_t, w, c, z, params_S) -> bool`
3.  **Σ-Protocol with Reduced PK and Proof Size (Fig 9)**
    *   `Sigma_Reduced_PK_Prover_P1(params_S_ds_T) -> (y, w)`
    *   `Sigma_Reduced_PK_Verifier_Challenge(params_C) -> c`
    *   `Sigma_Reduced_PK_Prover_P2(sk_s1_s2, pk_t, y, c, params_S_ds_T) -> (z, h)_or_⊥`
        *   Includes `HINT(Az - ct1, cto)`
    *   `Sigma_Reduced_PK_Verifier_Verify(pk_A_t1, w, c, z, h, params_S) -> bool`
        *   Includes `USEHINT(Az - ct1, h)`
4.  **Fiat-Shamir Transform for Signatures (Fig 10)**
    *   `FS_Sign(sk_s1_s2, pk_A_t_t1, μ, H_hash, Sigma_Prover_P1_func, Sigma_Prover_P2_func) -> signature_zh`
        *   Internally, `c = H_hash(w, μ, A, t)`
    *   `FS_Verify(pk_A_t_t1, μ, signature_zh, H_hash, Sigma_Verifier_Verify_func_adapted) -> bool`
        *   Internally, recomputes `c` and calls verifier.
5.  **CRYSTALS-Dilithium (ML-DSA) (Sec 5.7, based on Fig 10)**
    *   `Dilithium_KeyGen(params) -> (pk_rho_t1, sk_rho_K_tr_s1_s2)` (pk includes seed `ρ` for `A`)
    *   `Dilithium_Sign(sk, μ) -> signature_z_h_c`
    *   `Dilithium_Verify(pk, μ, signature_z_h_c) -> bool`

This list should cover the main algorithmic components.

---

Part 2: PRD File
=================

```prd
**Product Requirements Document: Lattice Cryptography Learning Toolkit**

**1. Introduction**
This document outlines the requirements for a "Lattice Cryptography Learning Toolkit," a software library designed to help developers understand the fundamental concepts of lattice-based cryptography. The toolkit will provide implementations of core algorithms and two prominent post-quantum cryptographic schemes: CRYSTALS-Kyber (ML-KEM) and CRYSTALS-Dilithium (ML-DSA), as detailed in V. Lyubashevsky's "Basic Lattice Cryptography" (Feb 14, 2025 update). The primary goal is educational, not production security.

**2. Goals**
*   To provide clear, understandable implementations of foundational lattice-based cryptographic primitives.
*   To allow users to experiment with Learning With Errors (LWE), Ring-LWE, and Module-LWE based encryption.
*   To implement the CRYSTALS-Kyber (ML-KEM) scheme.
*   To implement the CRYSTALS-Dilithium (ML-DSA) signature scheme.
*   To illustrate concepts like NTT, rejection sampling, and ciphertext/key compression.
*   To serve as a practical companion to the referenced academic paper.

**3. Target Audience**
*   Software developers and students interested in learning about post-quantum cryptography.
*   Researchers looking for a reference implementation for experimentation (non-production).

**4. Scope**
*   **In Scope:**
    *   Arithmetic in Zq and polynomial rings R_q,f.
    *   Number Theoretic Transform (NTT) for polynomial multiplication.
    *   Sampling from uniform and binomial distributions.
    *   Basic LWE-based encryption (as in Sec 2 of the paper).
    *   CRYSTALS-Kyber (ML-KEM) CPA and CCA KEM versions (Sec 4.7, 4.8).
    *   CRYSTALS-Dilithium (ML-DSA) signature scheme (Sec 5.7, based on Fig 10).
    *   Helper functions for compression/decompression and hint generation/usage.
*   **Out of Scope:**
    *   Production-level security hardening (e.g., side-channel resistance beyond what's in the paper's described algorithms like constant-time rejection sampling).
    *   Formal security proofs (the library implements schemes, proofs are in the paper).
    *   Advanced lattice problems or other lattice-based schemes not covered in detail (e.g., FHE, other signature schemes like Falcon).
    *   Graphical User Interface.
    *   Performance optimization beyond ensuring NTT is used correctly.

**5. Functional Requirements**

*   **FR1: Core Mathematical Primitives**
    *   FR1.1: Arithmetic operations (add, sub, mul, inv) in Zq.
    *   FR1.2: Representation and arithmetic (add, sub, mul, scalar_mul) for polynomials in R_q,f = Zq[X]/(f(X)). (Sec 4.1)
    *   FR1.3: Implementation of NTT and inverse NTT for X^d+1 and other suitable cyclotomic polynomials. (Sec 4.6)
    *   FR1.4: Sampling algorithms:
        *   Uniform sampling from Zq, [β].
        *   Sampling from binomial distribution ψn. (Def 8)
    *   FR1.5: Hashing utilities (SHA-3/SHAKE for PRF, general hashing for Fiat-Shamir). (External library acceptable)

*   **FR2: Basic LWE Encryption Module** (Based on Sec 2)
    *   FR2.1: `LWE_KeyGen_Basic`: Generate LWE public/private key pairs. (Sec 2.3.1, Eq 6)
    *   FR2.2: `LWE_Encrypt_Basic`: Encrypt a small message using an LWE public key. (Sec 2.3.1, Eq 7)
    *   FR2.3: `LWE_Decrypt_Basic`: Decrypt an LWE ciphertext using the secret key.
    *   FR2.4: Support for ciphertext compression/decompression techniques. (Sec 2.5.1, 2.5.2)

*   **FR3: CRYSTALS-Kyber (ML-KEM) Module** (Based on Sec 4.7, 4.8)
    *   FR3.1: `Kyber_CPA_KeyGen`: Generate Kyber CPA public/private key pairs according to specified parameter sets (e.g., Kyber-512). (Fig 3, Table 3)
    *   FR3.2: `Kyber_CPA_Encrypt`: Perform Kyber CPA encryption. (Fig 3)
    *   FR3.3: `Kyber_CPA_Decrypt`: Perform Kyber CPA decryption. (Fig 3)
    *   FR3.4: `Kyber_KEM_KeyGen`: Wrap CPA KeyGen for KEM. (Fig 4)
    *   FR3.5: `Kyber_KEM_Encaps`: Perform Kyber KEM encapsulation to generate a shared secret and ciphertext. (Fig 4)
    *   FR3.6: `Kyber_KEM_Decaps`: Perform Kyber KEM decapsulation to recover a shared secret. (Fig 4)
    *   FR3.7: Polynomials should be representable in NTT domain for efficiency. (Sec 4.7 discussion on page 39)

*   **FR4: CRYSTALS-Dilithium (ML-DSA) Module** (Based on Sec 5.7, Fig 10)
    *   FR4.1: `Dilithium_KeyGen`: Generate Dilithium public/private key pairs according to specified parameter sets. (Sec 5.7, Table 4)
        *   Public key `A` generated from a seed `ρ`.
    *   FR4.2: `Dilithium_Sign`: Generate a Dilithium signature for a message digest. (Fig 10)
        *   Must implement rejection sampling as described.
        *   Must implement `HINT` generation. (Sec 5.5)
    *   FR4.3: `Dilithium_Verify`: Verify a Dilithium signature for a message digest. (Fig 10)
        *   Must implement `USEHINT`. (Sec 5.5)
    *   FR4.4: Support for parameter sets (e.g., from Table 4).

**6. Non-Functional Requirements**
*   **NFR1: Correctness:** Implementations must correctly perform cryptographic operations as defined in the paper. Decryption must yield the original plaintext (barring specified negligible error rates). Verification must accept valid signatures.
*   **NFR2: Understandability:** Code should be well-commented and structured to facilitate learning, with references to sections/equations in the paper.
*   **NFR3: Testability:** Unit tests should cover core mathematical functions and cryptographic operations. Test vectors (if available from standards) should be used for Kyber/Dilithium.
*   **NFR4: Modularity:** Components (math, LWE, Kyber, Dilithium) should be logically separated.
*   **NFR5: Portability:** The core library should be platform-independent (Rust's strength).
*   **NFR6: Performance:** While not the primary goal, NTT-based polynomial multiplication should be efficient. Other operations should not be unnecessarily slow.

**7. Success Metrics**
*   All implemented cryptographic schemes pass known test vectors or round-trip encryption/signing tests.
*   Code coverage by unit tests exceeds 80%.
*   Users (e.g., project author) report a better understanding of the implemented lattice-based schemes.
*   The library can successfully interoperate with itself (e.g., a key generated can be used for encapsulation, and the resulting ciphertext decapsulated).

**8. Future Considerations (Out of Scope for Initial Version)**
*   Implementation of other schemes mentioned (e.g., basic NIKE, NTRU).
*   More advanced optimization techniques.
*   Bindings for other programming languages.
*   Visualizations or interactive demos.

```

---

Part 3: Rust Project Outline
=============================

This will be a Cargo workspace project.

**Workspace `Cargo.toml`:**
```toml
[workspace]
members = [
    "lattice-core",
    "kyber-ml-kem",
    "dilithium-ml-dsa",
    "examples"
]
```

**1. Crate: `lattice-core`**
    *Purpose:* Provides fundamental mathematical structures and operations.
    *Modules:*
        *   `params.rs`: Define structs for cryptographic parameters (q, n, k, eta, d_u, d_v for Kyber; q, f(X), beta, n, m, gamma, S, delta_s, T for Dilithium). Include constants from Tables 1, 2, 3, 4.
        *   `zq.rs`:
            *   Struct `ZqElement { value: u32, q: u32 }` (or similar, handle modulus q).
            *   Implement `Add, Sub, Mul, Neg` traits. Functions for `inverse`.
            *   Helper: `barrett_reduce` or other reduction methods.
        *   `polynomial.rs`:
            *   Struct `Polynomial { coeffs: Vec<ZqElement>, f_modulus_info: Option<PolyModulusInfo> }`. Coefficients could be `i16` or `i32` before reduction mod q for intermediate calculations.
            *   Implement `Add, Sub, Neg` for polynomials.
            *   `poly_mul(p1, p2, q, f)`: Schoolbook, Karatsuba, or (preferably) NTT-based multiplication. (Sec 4.1, 4.6)
            *   `poly_scalar_mul(scalar_zq, poly)`
            *   `poly_from_bytes(bytes, coeff_bits), poly_to_bytes(poly, coeff_bits)`
            *   `poly_compress(poly, q, target_bits), poly_decompress(poly_compressed, q, original_coeff_bits)` (Sec 2.5.2, applied to poly coeffs, used in Kyber Sec 4.7, Dilithium `HIGHS`/`LOWS` concepts Sec 5.4)
        *   `ntt.rs`: (Sec 4.6)
            *   `ntt_forward(poly, q, roots_of_unity)`
            *   `ntt_inverse(poly_ntt, q, inv_roots_of_unity)`
            *   `ntt_pointwise_mul(p1_ntt, p2_ntt)`
            *   `ntt_pointwise_add(p1_ntt, p2_ntt)`
            *   Functions to precompute roots of unity.
        *   `sampling.rs`:
            *   `sample_uniform(min, max_inclusive)` -> `i32` (or `ZqElement`)
            *   `sample_uniform_poly(param_beta, num_coeffs)` -> `Polynomial` (coeffs in `[-beta, beta]`)
            *   `sample_binomial(eta, num_coeffs)` -> `Polynomial` (coeffs from `ψ_eta`, Def 8)
            *   `sample_from_C(eta_challenge, d, num_coeffs)` for Dilithium challenge `c`. (Sec 5.1.1, Table 4)
        *   `vector_matrix.rs`:
            *   Structs for `PolyVector` and `PolyMatrix`.
            *   Operations: `vec_add`, `mat_vec_mul`, `transpose_vec_mul`.
        *   `hashing.rs`: (Wrappers around a crate like `sha3`)
            *   SHAKE128, SHAKE256, SHA3-256, SHA3-512.
            *   `prf(seed, nonce, len)`
            *   `hash_G(inputs...)`, `hash_H(inputs...)`

**2. Crate: `kyber-ml-kem`**
    *Purpose:* Implements CRYSTALS-Kyber (ML-KEM). (Sec 4.7, 4.8)
    *Dependencies:* `lattice-core`
    *Modules:*
        *   `params.rs`: Specific Kyber parameter sets (Kyber512, 768, 1024 from Table 3).
            *   `k, eta1, eta2, du, dv`. Kyber uses `f(X) = X^256 + 1` and `q = 3329`.
        *   `cpa.rs`: (Fig 3)
            *   `kyber_cpa_keygen(params) -> (pk_bytes, sk_bytes)`
                *   `pk = (rho, t_hat)` where `A_hat = NTT(GenA(rho))`, `t_hat = NTT(As+e)`
                *   `sk = s_hat` (NTT form of `s`)
            *   `kyber_cpa_encrypt(pk_bytes, msg_bytes, coins) -> ciphertext_bytes`
                *   `msg` is 32 bytes. `coins` is 32 bytes for randomness.
                *   Generates `r, e1, e2` from `coins` and `pk.rho` using `prf`.
                *   `u = Compress(InvNTT(A_hat * r_hat + e1_hat), du)`
                *   `v = Compress(InvNTT(t_hat * r_hat + e2_hat + Decompress(msg, 1)), dv)`
            *   `kyber_cpa_decrypt(sk_bytes, ciphertext_bytes) -> msg_bytes`
                *   `v' = Decompress(v, dv) - InvNTT(s_hat * NTT(Decompress(u, du)))`
                *   `msg = Compress(v', 1)`
        *   `kem.rs`: (Fig 4 + modifications from page 40)
            *   `kyber_kem_keygen() -> (pk_bytes, sk_bytes_kem)`
                *   `sk_bytes_kem` includes CPA `sk`, `pk`, pre-hashed `pk` (`h_pk`), and a random `z` (256 bits).
            *   `kyber_kem_encaps(pk_bytes) -> (shared_secret_K_bytes, ciphertext_c_bytes)`
                *   Generate random `m` (256 bits).
                *   `(K, r_coins) = G(m, H(pk))`.
                *   `c = CPA_Encrypt(pk, m, r_coins)`.
            *   `kyber_kem_decaps(sk_bytes_kem, ciphertext_c_bytes) -> shared_secret_K_bytes`
                *   `m_prime = CPA_Decrypt(cpa_sk, c)`.
                *   `(K_prime, r_coins_prime) = G(m_prime, h_pk)`.
                *   `c_prime = CPA_Encrypt(pk, m_prime, r_coins_prime)`.
                *   If `c == c_prime`, return `K_prime`. Else return `H(z, c)`.

**3. Crate: `dilithium-ml-dsa`**
    *Purpose:* Implements CRYSTALS-Dilithium (ML-DSA). (Sec 5.7, Fig 10)
    *Dependencies:* `lattice-core`
    *Modules:*
        *   `params.rs`: Specific Dilithium parameter sets (e.g., Dilithium2, 3, 5, Table 4 provides one example).
            *   `k, l, eta, gamma1, gamma2, beta (tau), omega`. Uses `f(X) = X^256 + 1`, `q = 2^23 - 2^13 + 1`.
            *   Define `HIGHS`, `LOWS`, `HINT`, `USEHINT` related parameters (`delta_s` from `q/2^k_S`).
        *   `sign.rs`:
            *   `dilithium_keygen() -> (pk_bytes, sk_bytes)`
                *   `pk = (rho, t1)` where `A` from `rho`, `t = As1+s2`, `t1=HIGHS(t, gamma2)`. (Sec 5.5, `t0=LOWS(t,gamma2)`)
                *   `sk = (rho, K, tr, s1, s2, t0)` where `K` is for PRF for `y`, `tr` is H(pk, mu) for challenges.
            *   `dilithium_sign(sk_bytes, msg_bytes) -> signature_bytes` (Fig 10)
                *   Expand `A` from `sk.rho`.
                *   Loop (rejection sampling):
                    *   Sample `y` (coeffs bounded by `gamma1 - eta`).
                    *   `w1 = HIGHS(Ay, gamma2)`. (Sec 5.4, Fig 8 `w=HIGHS(Ay)`)
                    *   `c_tilde = H(tr, msg)`. ( Fiat-Shamir, `tr` contains `w1` essentially).
                    *   `c = SampleInBall(c_tilde, tau)`. (Challenge from `C`)
                    *   `z = y + cs1`.
                    *   Check bounds on `z` and `LOWS(w - cs2, gamma2)`. If fail, continue loop.
                    *   `h = MakeHint(-cs2, w1 - Az + ct0, omega)`. (`ct0` part, see Sec 5.5, Fig 9's hint is `HINT(Az-ct1, cto)`)
                    *   Return `(z, h, c)`.
            *   `dilithium_verify(pk_bytes, msg_bytes, signature_bytes) -> bool` (Fig 10)
                *   Expand `A` from `pk.rho`, `t1` from `pk`.
                *   Parse `(z, h, c)` from signature.
                *   Check bounds on `z`.
                *   `w1_prime = UseHint(h, Az - ct1, omega)`.
                *   `c_tilde_prime = H(H(pk.rho, pk.t1), msg)`. (recompute challenge seed)
                *   `c_prime = SampleInBall(c_tilde_prime, tau)`.
                *   Return `c == c_prime` and `h` has correct number of 1s.

**4. Crate: `examples`**
    *Purpose:* Demonstrate usage of Kyber and Dilithium.
    *   `kyber_example.rs`: Keygen, encaps, decaps. Print intermediate values.
    *   `dilithium_example.rs`: Keygen, sign, verify. Print intermediate values.

**Implementation Notes for Rust:**
*   Use `i32` for polynomial coefficients generally, as they can be negative and intermediate products can exceed `i16`. Modulo `q` operations will keep them in Zq.
*   For NTT, coefficients might be in standard order or bit-reversed order. Be consistent.
*   Sampling functions are critical. Use a good CSPRNG (e.g., from `rand` crate, seeded appropriately for deterministic parts if needed like in Kyber encryption from `coins`).
*   Carefully manage byte serialization/deserialization according to Kyber/Dilithium specs if aiming for interoperability (NIST FIPS 203, 204, 205). For learning, a consistent internal format is fine first.
*   The "hint" mechanism in Dilithium (Sec 5.5 and Fig 9, 10) is subtle. `HINT(v, r)` where `v` is the "high bits" part and `r` is the "carry/remainder" part. `USEHINT(v,h)` reconstructs the high bits of `v-r`.
*   Kyber's `du, dv` and Dilithium's `gamma1, gamma2` control compression and thus affect noise bounds and decryption/signing correctness.
*   Rejection sampling in Dilithium (Fig 10, "RESTART") is crucial for security. The bounds check on `z` (norm) and `LOWS(Ay-cs2)` (or `w0 - cs2` effectively) (norm) ensure the signature doesn't leak `s1, s2`.

This outline provides a good starting point. You'll discover many details as you implement, especially around parameter choices and exact formulas for compression/hinting. Good luck, it's a fantastic way to learn!