pub mod params;
pub mod zq;
pub mod polynomial;
pub mod ntt;
pub mod sampling;
pub mod vector_matrix;
pub mod hashing;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
} 