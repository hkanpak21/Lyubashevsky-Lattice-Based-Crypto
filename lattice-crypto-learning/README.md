# Lattice Cryptography Learning Toolkit

This project provides a Rust implementation of lattice-based cryptography primitives based on the paper "Basic Lattice Cryptography" by V. Lyubashevsky (Feb 14, 2025 update).

The primary focus is on educational value rather than production-level security or performance. The code is designed to be clear, well-documented, and to illustrate the core concepts of lattice-based cryptography.

## Structure

The project is organized as a Cargo workspace with the following crates:

- `lattice-core`: Core mathematical primitives for lattice cryptography
- `kyber-ml-kem`: Implementation of CRYSTALS-Kyber (ML-KEM) key encapsulation mechanism
- `dilithium-ml-dsa`: Implementation of CRYSTALS-Dilithium (ML-DSA) digital signature algorithm (coming soon)
- `examples`: Example applications demonstrating the usage of the primitives

## Features

### Lattice Core
- Arithmetic in Z_q and polynomial rings R_q,f
- Number Theoretic Transform (NTT) for efficient polynomial multiplication
- Sampling from uniform and binomial distributions
- Vector/matrix operations for Module-LWE/SIS

### Kyber (ML-KEM)
- Implementation of CRYSTALS-Kyber key encapsulation mechanism
- Support for Kyber-512, Kyber-768, and Kyber-1024 parameter sets
- Both CPA-secure encryption and CCA-secure KEM variants

### Dilithium (ML-DSA)
- Coming soon: Implementation of CRYSTALS-Dilithium signature scheme

## Getting Started

### Prerequisites
- Rust 1.70 or newer
- Cargo

### Building
```bash
git clone https://github.com/yourusername/lattice-crypto-learning.git
cd lattice-crypto-learning
cargo build
```

### Running Examples
```bash
# Run the Kyber example
cargo run --bin kyber_example

# Run the Dilithium example (coming soon)
cargo run --bin dilithium_example
```

## Educational Value

This project aims to help developers and cryptography enthusiasts understand:

1. The mathematical foundations of lattice-based cryptography
2. The Learning With Errors (LWE) and Ring-LWE problems
3. The structure and implementation of post-quantum cryptographic schemes
4. Efficient algorithms like the Number Theoretic Transform for polynomial multiplication

The code includes comprehensive comments explaining the algorithms and relating them to the source paper.

## Security Notice

This implementation is NOT intended for production use. It is designed for educational purposes and may lack important security features such as:

- Constant-time implementation for all operations
- Complete side-channel resistance
- Thorough security auditing

For production applications, please use established libraries like:
- [Liboqs](https://github.com/open-quantum-safe/liboqs)
- [PQClean](https://github.com/PQClean/PQClean)
- [CRYSTALS-Kyber](https://github.com/pq-crystals/kyber)
- [CRYSTALS-Dilithium](https://github.com/pq-crystals/dilithium)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The implementation is based on the paper "Basic Lattice Cryptography" by V. Lyubashevsky
- Inspired by the NIST Post-Quantum Cryptography standardization process
- Special thanks to the CRYSTALS team for their clear specifications 