use anyhow::Result;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use password_hash::SaltString;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("unable to hash password: {e}"))?
        .to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

pub fn password_hash_is_production_grade(encoded: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|hash| {
        hash.algorithm.as_str() == "argon2id"
            && hash.params.get_decimal("m").is_some_and(|v| v >= 19_456)
            && hash.params.get_decimal("t").is_some_and(|v| v >= 2)
            && hash.params.get_decimal("p").is_some_and(|v| v >= 1)
    })
}

pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn password_hashes_are_salted_and_verify() {
        let a = hash_password("correct horse").unwrap();
        let b = hash_password("correct horse").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("correct horse", &a));
        assert!(!verify_password("wrong", &a));
        assert!(password_hash_is_production_grade(&a));
        assert!(!password_hash_is_production_grade("$argon2id$broken"));
    }
    #[test]
    fn tokens_have_full_entropy_shape() {
        let a = new_token();
        let b = new_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(token_hash(&a).len(), 64);
    }
}
