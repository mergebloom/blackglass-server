use anyhow::Result;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use password_hash::SaltString;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

const MIN_ARGON2_MEMORY_KIB: u32 = 19_456;
const MAX_ARGON2_MEMORY_KIB: u32 = 65_536;
const MIN_ARGON2_TIME_COST: u32 = 2;
const MAX_ARGON2_TIME_COST: u32 = 5;
const MIN_ARGON2_PARALLELISM: u32 = 1;
const MAX_ARGON2_PARALLELISM: u32 = 4;
const MAX_PASSWORD_HASH_LENGTH: usize = 512;

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("unable to hash password: {e}"))?
        .to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    accepted_password_hash(encoded).is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

pub fn password_hash_is_production_grade(encoded: &str) -> bool {
    accepted_password_hash(encoded).is_some()
}

fn accepted_password_hash(encoded: &str) -> Option<PasswordHash<'_>> {
    if encoded.len() > MAX_PASSWORD_HASH_LENGTH {
        return None;
    }
    let hash = PasswordHash::new(encoded).ok()?;
    let memory = hash.params.get_decimal("m")?;
    let time = hash.params.get_decimal("t")?;
    let parallelism = hash.params.get_decimal("p")?;
    let salt_length = hash.salt?.as_str().len();
    let output_length = hash.hash?.len();
    let mut parameter_names = hash
        .params
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    parameter_names.sort_unstable();
    (hash.algorithm.as_str() == "argon2id"
        && hash.version == Some(19)
        && parameter_names == ["m", "p", "t"]
        && (MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&memory)
        && (MIN_ARGON2_TIME_COST..=MAX_ARGON2_TIME_COST).contains(&time)
        && (MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&parallelism)
        && (8..=64).contains(&salt_length)
        && (16..=64).contains(&output_length))
    .then_some(hash)
}

pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn new_managed_vault_credentials() -> (String, String) {
    let mut password = [0u8; 32];
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut password);
    OsRng.fill_bytes(&mut salt);
    (hex::encode(password), hex::encode(salt))
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
    fn password_hash_policy_rejects_unbounded_or_malformed_work_before_verification() {
        let encoded = hash_password("correct horse").unwrap();
        for rejected in [
            with_argon2_params(&encoded, 19_455, 2, 1),
            with_argon2_params(&encoded, 65_537, 2, 1),
            with_argon2_params(&encoded, 19_456, 1, 1),
            with_argon2_params(&encoded, 19_456, 6, 1),
            with_argon2_params(&encoded, 19_456, 2, 0),
            with_argon2_params(&encoded, 19_456, 2, 5),
            with_argon2_params(&encoded, u32::MAX, u32::MAX, u32::MAX),
            encoded.replacen("p=1", "p=1,x=1", 1),
            encoded.replace("$v=19$", "$v=16$"),
            format!("{encoded}{}", "x".repeat(MAX_PASSWORD_HASH_LENGTH)),
        ] {
            assert!(!password_hash_is_production_grade(&rejected));
            assert!(!verify_password("correct horse", &rejected));
        }
        let bounded = with_argon2_params(
            &encoded,
            MAX_ARGON2_MEMORY_KIB,
            MAX_ARGON2_TIME_COST,
            MAX_ARGON2_PARALLELISM,
        );
        assert!(password_hash_is_production_grade(&bounded));
    }

    fn with_argon2_params(encoded: &str, memory: u32, time: u32, parallelism: u32) -> String {
        let parts = encoded.split('$').collect::<Vec<_>>();
        assert_eq!(parts.len(), 6);
        format!(
            "$argon2id$v=19$m={memory},t={time},p={parallelism}${}${}",
            parts[4], parts[5]
        )
    }
    #[test]
    fn tokens_have_full_entropy_shape() {
        let a = new_token();
        let b = new_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(token_hash(&a).len(), 64);
    }
    #[test]
    fn managed_vault_credentials_have_full_entropy_shape() {
        let (password_a, salt_a) = new_managed_vault_credentials();
        let (password_b, salt_b) = new_managed_vault_credentials();
        assert_eq!(password_a.len(), 64);
        assert_eq!(salt_a.len(), 32);
        assert_ne!(password_a, password_b);
        assert_ne!(salt_a, salt_b);
        assert!(password_a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(salt_a.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
