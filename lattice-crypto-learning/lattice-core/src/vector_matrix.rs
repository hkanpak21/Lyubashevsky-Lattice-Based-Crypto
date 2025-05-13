use std::ops::{Add, Sub, Mul};
use crate::polynomial::Polynomial;
use crate::params::PolyModulusInfo;
use crate::ntt::{ntt_forward, ntt_inverse, ntt_pointwise_mul, NTTParams};

/// Represents a vector of polynomials
#[derive(Debug, Clone, PartialEq)]
pub struct PolyVector {
    /// Vector of polynomials
    pub entries: Vec<Polynomial>,
    /// Modulus info for all polynomials
    pub modulus_info: PolyModulusInfo,
}

/// Represents a matrix of polynomials
#[derive(Debug, Clone, PartialEq)]
pub struct PolyMatrix {
    /// Matrix of polynomials in row-major order
    pub rows: Vec<PolyVector>,
    /// Modulus info for all polynomials
    pub modulus_info: PolyModulusInfo,
    /// Number of rows
    pub n_rows: usize,
    /// Number of columns
    pub n_cols: usize,
}

impl PolyVector {
    /// Creates a new vector of polynomials
    pub fn new(entries: Vec<Polynomial>, modulus_info: PolyModulusInfo) -> Self {
        for poly in &entries {
            assert_eq!(poly.modulus_info.q, modulus_info.q, 
                      "All polynomials must have the same modulus");
            assert_eq!(poly.modulus_info.degree, modulus_info.degree, 
                      "All polynomials must have the same degree");
        }
        
        Self { entries, modulus_info }
    }
    
    /// Creates a zero vector of given length
    pub fn zero(length: usize, modulus_info: PolyModulusInfo) -> Self {
        let entries = (0..length)
            .map(|_| Polynomial::zero(modulus_info))
            .collect();
        
        Self { entries, modulus_info }
    }
    
    /// Returns the length of the vector
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Checks if the vector is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    
    /// Computes the inner product with another vector
    pub fn inner_product(&self, other: &Self, ntt_params: Option<&NTTParams>) -> Polynomial {
        assert_eq!(self.len(), other.len(), "Vectors must have the same length");
        assert_eq!(self.modulus_info.q, other.modulus_info.q, 
                  "Vectors must have the same modulus");
        
        if self.is_empty() {
            return Polynomial::zero(self.modulus_info);
        }
        
        // Initialize result to zero polynomial
        let mut result = Polynomial::zero(self.modulus_info);
        
        // If NTT params are provided, use NTT-based multiplication
        if let Some(params) = ntt_params {
            // Check if polynomials are already in NTT form
            let use_ntt = !self.entries[0].modulus_info.is_ntt_form;
            
            for i in 0..self.len() {
                let product = if use_ntt {
                    // Convert to NTT domain, multiply, convert back
                    let a_ntt = ntt_forward(&self.entries[i], params);
                    let b_ntt = ntt_forward(&other.entries[i], params);
                    let prod_ntt = ntt_pointwise_mul(&a_ntt, &b_ntt);
                    ntt_inverse(&prod_ntt, params)
                } else {
                    // Already in NTT domain, just do pointwise multiplication
                    let prod_ntt = ntt_pointwise_mul(&self.entries[i], &other.entries[i]);
                    ntt_inverse(&prod_ntt, params)
                };
                
                // Add to result
                result = result + product;
            }
        } else {
            // Use schoolbook multiplication
            for i in 0..self.len() {
                let product = self.entries[i].schoolbook_mul(&other.entries[i]);
                result = result + product;
            }
        }
        
        result
    }
    
    /// Adds a constant polynomial to each entry
    pub fn add_constant(&self, constant: &Polynomial) -> Self {
        assert_eq!(self.modulus_info.q, constant.modulus_info.q,
                  "Moduli must match");
        
        let entries = self.entries.iter()
            .map(|poly| poly.clone() + constant.clone())
            .collect();
        
        Self {
            entries,
            modulus_info: self.modulus_info,
        }
    }
    
    /// Converts to bytes for serialization
    pub fn to_bytes(&self, coeff_bits: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Store each polynomial
        for poly in &self.entries {
            bytes.extend_from_slice(&poly.to_bytes(coeff_bits));
        }
        
        bytes
    }
    
    /// Creates from bytes
    pub fn from_bytes(bytes: &[u8], modulus_info: PolyModulusInfo, length: usize, coeff_bits: usize) -> Self {
        let n = modulus_info.degree;
        let bytes_per_poly = n * ((coeff_bits + 7) / 8);
        
        assert!(bytes.len() >= length * bytes_per_poly, "Not enough bytes");
        
        let mut entries = Vec::with_capacity(length);
        
        for i in 0..length {
            let start = i * bytes_per_poly;
            let end = start + bytes_per_poly;
            let poly_bytes = &bytes[start..end];
            
            let poly = Polynomial::from_bytes(poly_bytes, modulus_info, coeff_bits);
            entries.push(poly);
        }
        
        Self { entries, modulus_info }
    }
    
    /// Computes infinity norm (maximum infinity norm of any polynomial)
    pub fn infinity_norm(&self) -> i32 {
        self.entries.iter()
            .map(|poly| poly.infinity_norm())
            .max()
            .unwrap_or(0)
    }
}

impl PolyMatrix {
    /// Creates a new matrix from rows
    pub fn new(rows: Vec<PolyVector>, n_rows: usize, n_cols: usize, modulus_info: PolyModulusInfo) -> Self {
        assert_eq!(rows.len(), n_rows, "Number of rows must match");
        for row in &rows {
            assert_eq!(row.len(), n_cols, "All rows must have the same length");
            assert_eq!(row.modulus_info.q, modulus_info.q, "All rows must have the same modulus");
        }
        
        Self { rows, modulus_info, n_rows, n_cols }
    }
    
    /// Creates a zero matrix of given dimensions
    pub fn zero(n_rows: usize, n_cols: usize, modulus_info: PolyModulusInfo) -> Self {
        let rows = (0..n_rows)
            .map(|_| PolyVector::zero(n_cols, modulus_info))
            .collect();
        
        Self { rows, modulus_info, n_rows, n_cols }
    }
    
    /// Gets a reference to an entry
    pub fn get(&self, row: usize, col: usize) -> Option<&Polynomial> {
        self.rows.get(row)?.entries.get(col)
    }
    
    /// Gets a mutable reference to an entry
    pub fn get_mut(&mut self, row: usize, col: usize) -> Option<&mut Polynomial> {
        self.rows.get_mut(row)?.entries.get_mut(col)
    }
    
    /// Matrix-vector multiplication
    pub fn mul_vec(&self, vec: &PolyVector, ntt_params: Option<&NTTParams>) -> PolyVector {
        assert_eq!(self.n_cols, vec.len(), "Matrix columns must match vector length");
        assert_eq!(self.modulus_info.q, vec.modulus_info.q, "Moduli must match");
        
        let mut result_entries = Vec::with_capacity(self.n_rows);
        
        for i in 0..self.n_rows {
            // Compute dot product of row i with vector
            let product = self.rows[i].inner_product(vec, ntt_params);
            result_entries.push(product);
        }
        
        PolyVector::new(result_entries, self.modulus_info)
    }
    
    /// Matrix-matrix multiplication
    pub fn mul_mat(&self, other: &PolyMatrix, ntt_params: Option<&NTTParams>) -> PolyMatrix {
        assert_eq!(self.n_cols, other.n_rows, "Inner dimensions must match");
        assert_eq!(self.modulus_info.q, other.modulus_info.q, "Moduli must match");
        
        let mut result_rows = Vec::with_capacity(self.n_rows);
        
        for i in 0..self.n_rows {
            let mut row_entries = Vec::with_capacity(other.n_cols);
            
            for j in 0..other.n_cols {
                // Create a column vector from the jth column of other
                let column: PolyVector = PolyVector::new(
                    (0..other.n_rows)
                        .map(|k| other.rows[k].entries[j].clone())
                        .collect(),
                    self.modulus_info
                );
                
                // Compute dot product of row i with column j
                let product = self.rows[i].inner_product(&column, ntt_params);
                row_entries.push(product);
            }
            
            result_rows.push(PolyVector::new(row_entries, self.modulus_info));
        }
        
        PolyMatrix::new(result_rows, self.n_rows, other.n_cols, self.modulus_info)
    }
    
    /// Transpose of the matrix
    pub fn transpose(&self) -> PolyMatrix {
        let mut result_rows = Vec::with_capacity(self.n_cols);
        
        for j in 0..self.n_cols {
            let row_entries: Vec<Polynomial> = (0..self.n_rows)
                .map(|i| self.rows[i].entries[j].clone())
                .collect();
            
            result_rows.push(PolyVector::new(row_entries, self.modulus_info));
        }
        
        PolyMatrix::new(result_rows, self.n_cols, self.n_rows, self.modulus_info)
    }
    
    /// Converts to NTT domain
    pub fn to_ntt_domain(&self, params: &NTTParams) -> PolyMatrix {
        let ntt_rows: Vec<PolyVector> = self.rows.iter()
            .map(|row| {
                let ntt_entries: Vec<Polynomial> = row.entries.iter()
                    .map(|poly| ntt_forward(poly, params))
                    .collect();
                
                PolyVector::new(ntt_entries, PolyModulusInfo {
                    degree: self.modulus_info.degree,
                    q: self.modulus_info.q,
                    is_ntt_form: true,
                })
            })
            .collect();
        
        PolyMatrix::new(ntt_rows, self.n_rows, self.n_cols, PolyModulusInfo {
            degree: self.modulus_info.degree,
            q: self.modulus_info.q,
            is_ntt_form: true,
        })
    }
    
    /// Converts from NTT domain
    pub fn from_ntt_domain(&self, params: &NTTParams) -> PolyMatrix {
        assert!(self.modulus_info.is_ntt_form, "Matrix must be in NTT form");
        
        let std_rows: Vec<PolyVector> = self.rows.iter()
            .map(|row| {
                let std_entries: Vec<Polynomial> = row.entries.iter()
                    .map(|poly| ntt_inverse(poly, params))
                    .collect();
                
                PolyVector::new(std_entries, PolyModulusInfo {
                    degree: self.modulus_info.degree,
                    q: self.modulus_info.q,
                    is_ntt_form: false,
                })
            })
            .collect();
        
        PolyMatrix::new(std_rows, self.n_rows, self.n_cols, PolyModulusInfo {
            degree: self.modulus_info.degree,
            q: self.modulus_info.q,
            is_ntt_form: false,
        })
    }
}

impl Add for PolyVector {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        assert_eq!(self.len(), other.len(), "Vectors must have the same length");
        assert_eq!(self.modulus_info.q, other.modulus_info.q, "Moduli must match");
        
        let entries = self.entries.iter()
            .zip(other.entries.iter())
            .map(|(a, b)| a.clone() + b.clone())
            .collect();
        
        Self {
            entries,
            modulus_info: self.modulus_info,
        }
    }
}

impl Sub for PolyVector {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        assert_eq!(self.len(), other.len(), "Vectors must have the same length");
        assert_eq!(self.modulus_info.q, other.modulus_info.q, "Moduli must match");
        
        let entries = self.entries.iter()
            .zip(other.entries.iter())
            .map(|(a, b)| a.clone() - b.clone())
            .collect();
        
        Self {
            entries,
            modulus_info: self.modulus_info,
        }
    }
}

impl Add for PolyMatrix {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        assert_eq!(self.n_rows, other.n_rows, "Matrices must have the same number of rows");
        assert_eq!(self.n_cols, other.n_cols, "Matrices must have the same number of columns");
        assert_eq!(self.modulus_info.q, other.modulus_info.q, "Moduli must match");
        
        let rows = self.rows.iter()
            .zip(other.rows.iter())
            .map(|(a, b)| a.clone() + b.clone())
            .collect();
        
        Self {
            rows,
            modulus_info: self.modulus_info,
            n_rows: self.n_rows,
            n_cols: self.n_cols,
        }
    }
}

impl Sub for PolyMatrix {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        assert_eq!(self.n_rows, other.n_rows, "Matrices must have the same number of rows");
        assert_eq!(self.n_cols, other.n_cols, "Matrices must have the same number of columns");
        assert_eq!(self.modulus_info.q, other.modulus_info.q, "Moduli must match");
        
        let rows = self.rows.iter()
            .zip(other.rows.iter())
            .map(|(a, b)| a.clone() - b.clone())
            .collect();
        
        Self {
            rows,
            modulus_info: self.modulus_info,
            n_rows: self.n_rows,
            n_cols: self.n_cols,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zq::ZqElement;
    
    fn create_test_modulus() -> PolyModulusInfo {
        PolyModulusInfo {
            degree: 4,
            q: 17,
            is_ntt_form: false,
        }
    }
    
    fn create_test_poly(coeffs: &[i32], modulus_info: PolyModulusInfo) -> Polynomial {
        let q = modulus_info.q;
        let zq_coeffs = coeffs.iter()
            .map(|&c| ZqElement::new(c, q))
            .collect();
        
        Polynomial::new(zq_coeffs, modulus_info)
    }
    
    #[test]
    fn test_vector_creation() {
        let modulus = create_test_modulus();
        let p1 = create_test_poly(&[1, 2, 3, 4], modulus);
        let p2 = create_test_poly(&[5, 6, 7, 8], modulus);
        
        let vec = PolyVector::new(vec![p1, p2], modulus);
        
        assert_eq!(vec.len(), 2);
        assert_eq!(vec.modulus_info.q, 17);
    }
    
    #[test]
    fn test_vector_addition() {
        let modulus = create_test_modulus();
        
        let p1 = create_test_poly(&[1, 2, 3, 4], modulus);
        let p2 = create_test_poly(&[5, 6, 7, 8], modulus);
        let v1 = PolyVector::new(vec![p1, p2.clone()], modulus);
        
        let p3 = create_test_poly(&[2, 3, 4, 5], modulus);
        let p4 = create_test_poly(&[6, 7, 8, 9], modulus);
        let v2 = PolyVector::new(vec![p3, p4], modulus);
        
        let result = v1 + v2;
        
        // Expected: [3, 5, 7, 9], [11, 13, 15, 17 mod 17 = 0]
        let expected_p1 = create_test_poly(&[3, 5, 7, 9], modulus);
        let expected_p2 = create_test_poly(&[11, 13, 15, 0], modulus);
        
        assert_eq!(result.entries[0], expected_p1);
        assert_eq!(result.entries[1], expected_p2);
    }
    
    #[test]
    fn test_inner_product() {
        let modulus = create_test_modulus();
        
        let p1 = create_test_poly(&[1, 2, 0, 0], modulus);
        let p2 = create_test_poly(&[3, 4, 0, 0], modulus);
        let v1 = PolyVector::new(vec![p1, p2], modulus);
        
        let p3 = create_test_poly(&[2, 0, 0, 0], modulus);
        let p4 = create_test_poly(&[5, 0, 0, 0], modulus);
        let v2 = PolyVector::new(vec![p3, p4], modulus);
        
        let result = v1.inner_product(&v2, None);
        
        // Expected: (1,2,0,0)*(2,0,0,0) + (3,4,0,0)*(5,0,0,0)
        // = (2,4,0,0) + (15,20,0,0) = (17,24,0,0) mod 17 = (0,7,0,0)
        let expected = create_test_poly(&[0, 7, 0, 0], modulus);
        
        assert_eq!(result, expected);
    }
    
    #[test]
    fn test_matrix_creation() {
        let modulus = create_test_modulus();
        
        let p1 = create_test_poly(&[1, 2, 0, 0], modulus);
        let p2 = create_test_poly(&[3, 4, 0, 0], modulus);
        let row1 = PolyVector::new(vec![p1, p2], modulus);
        
        let p3 = create_test_poly(&[5, 6, 0, 0], modulus);
        let p4 = create_test_poly(&[7, 8, 0, 0], modulus);
        let row2 = PolyVector::new(vec![p3, p4], modulus);
        
        let matrix = PolyMatrix::new(vec![row1, row2], 2, 2, modulus);
        
        assert_eq!(matrix.n_rows, 2);
        assert_eq!(matrix.n_cols, 2);
        assert_eq!(matrix.modulus_info.q, 17);
    }
    
    #[test]
    fn test_matrix_vector_multiplication() {
        let modulus = create_test_modulus();
        
        // Matrix:
        // [1 2]
        // [3 4]
        let p1 = create_test_poly(&[1, 0, 0, 0], modulus);
        let p2 = create_test_poly(&[2, 0, 0, 0], modulus);
        let row1 = PolyVector::new(vec![p1, p2], modulus);
        
        let p3 = create_test_poly(&[3, 0, 0, 0], modulus);
        let p4 = create_test_poly(&[4, 0, 0, 0], modulus);
        let row2 = PolyVector::new(vec![p3, p4], modulus);
        
        let matrix = PolyMatrix::new(vec![row1, row2], 2, 2, modulus);
        
        // Vector: [5, 6]
        let v1 = create_test_poly(&[5, 0, 0, 0], modulus);
        let v2 = create_test_poly(&[6, 0, 0, 0], modulus);
        let vector = PolyVector::new(vec![v1, v2], modulus);
        
        let result = matrix.mul_vec(&vector, None);
        
        // Expected: [1*5 + 2*6, 3*5 + 4*6] = [17, 39] mod 17 = [0, 5]
        let expected_p1 = create_test_poly(&[0, 0, 0, 0], modulus);
        let expected_p2 = create_test_poly(&[5, 0, 0, 0], modulus);
        
        assert_eq!(result.entries[0], expected_p1);
        assert_eq!(result.entries[1], expected_p2);
    }
    
    #[test]
    fn test_matrix_transpose() {
        let modulus = create_test_modulus();
        
        // Matrix:
        // [1 2 3]
        // [4 5 6]
        let p1 = create_test_poly(&[1, 0, 0, 0], modulus);
        let p2 = create_test_poly(&[2, 0, 0, 0], modulus);
        let p3 = create_test_poly(&[3, 0, 0, 0], modulus);
        let row1 = PolyVector::new(vec![p1, p2, p3], modulus);
        
        let p4 = create_test_poly(&[4, 0, 0, 0], modulus);
        let p5 = create_test_poly(&[5, 0, 0, 0], modulus);
        let p6 = create_test_poly(&[6, 0, 0, 0], modulus);
        let row2 = PolyVector::new(vec![p4, p5, p6], modulus);
        
        let matrix = PolyMatrix::new(vec![row1, row2], 2, 3, modulus);
        
        let transposed = matrix.transpose();
        
        // Expected:
        // [1 4]
        // [2 5]
        // [3 6]
        assert_eq!(transposed.n_rows, 3);
        assert_eq!(transposed.n_cols, 2);
        
        assert_eq!(transposed.rows[0].entries[0].coeffs[0].value(), 1);
        assert_eq!(transposed.rows[0].entries[1].coeffs[0].value(), 4);
        assert_eq!(transposed.rows[1].entries[0].coeffs[0].value(), 2);
        assert_eq!(transposed.rows[1].entries[1].coeffs[0].value(), 5);
        assert_eq!(transposed.rows[2].entries[0].coeffs[0].value(), 3);
        assert_eq!(transposed.rows[2].entries[1].coeffs[0].value(), 6);
    }
} 