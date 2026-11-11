use std::{fmt, sync::Arc};

use anyhow::{Result, anyhow, bail, ensure};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash as PhcHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::{TryRng, rngs::SysRng};

pub const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum PasswordAlgorithm {
    Argon2id,
    Bcrypt,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash {
    encoded: Arc<str>,
    profile: VerificationProfile,
}

#[derive(Clone, PartialEq, Eq)]
enum VerificationProfile {
    Argon2id { params: Params, salt_len: usize },
    Bcrypt { cost: u32 },
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordHash([redacted])")
    }
}

pub fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
}

pub fn valid_password(password: &str) -> bool {
    !password.is_empty()
        && password.len() <= MAX_PASSWORD_BYTES
        && !password.bytes().any(|byte| byte.is_ascii_control())
}

impl PasswordHash {
    pub fn parse(encoded: &str) -> Result<Self> {
        ensure!(encoded.len() <= 512, "invalid password hash encoding");
        let profile = if encoded.starts_with("$argon2id$") {
            let hash =
                PhcHash::new(encoded).map_err(|_| anyhow!("invalid Argon2id password hash"))?;
            ensure!(
                hash.version == Some(19),
                "Argon2id hash must use version 19"
            );
            ensure!(
                hash.salt.is_some() && hash.hash.is_some(),
                "incomplete Argon2id password hash"
            );
            let mut salt = [0; 64];
            let salt = hash
                .salt
                .expect("checked salt")
                .decode_b64(&mut salt)
                .map_err(|_| anyhow!("invalid Argon2id salt"))?;
            ensure!(
                salt.len() >= argon2::MIN_SALT_LEN,
                "Argon2id salt is too short"
            );
            let params =
                Params::try_from(&hash).map_err(|_| anyhow!("invalid Argon2id parameters"))?;
            ensure!(
                params.m_cost() <= 262_144 && params.t_cost() <= 10 && params.p_cost() <= 8,
                "Argon2id password hash exceeds verification cost limits"
            );
            VerificationProfile::Argon2id {
                params,
                salt_len: salt.len(),
            }
        } else if ["$2a$", "$2b$", "$2y$"]
            .iter()
            .any(|prefix| encoded.starts_with(prefix))
        {
            ensure!(encoded.len() == 60, "invalid bcrypt password hash");
            let parts: bcrypt::HashParts = encoded
                .parse()
                .map_err(|_| anyhow!("invalid bcrypt password hash"))?;
            ensure!(
                (4..=16).contains(&parts.get_cost()),
                "bcrypt password hash cost must be between 4 and 16"
            );
            VerificationProfile::Bcrypt {
                cost: parts.get_cost(),
            }
        } else {
            bail!("unsupported password hash; use Argon2id or bcrypt");
        };
        Ok(Self {
            encoded: encoded.into(),
            profile,
        })
    }

    pub(crate) fn same_profile(&self, other: &Self) -> bool {
        self.profile == other.profile
    }

    pub(crate) fn verify(&self, password: &str) -> bool {
        if !valid_password(password) {
            return false;
        }
        match &self.profile {
            VerificationProfile::Argon2id { .. } => PhcHash::new(&self.encoded).is_ok_and(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            }),
            VerificationProfile::Bcrypt { .. } => {
                password.len() <= 72
                    && bcrypt::non_truncating_verify(password, &self.encoded).unwrap_or(false)
            }
        }
    }
}

pub fn generate_hash(password: &str, algorithm: PasswordAlgorithm) -> Result<String> {
    ensure!(
        valid_password(password),
        "password must contain 1 to 1024 bytes without control characters"
    );
    match algorithm {
        PasswordAlgorithm::Argon2id => {
            let mut salt = [0; 16];
            SysRng
                .try_fill_bytes(&mut salt)
                .map_err(|_| anyhow!("failed to generate password salt"))?;
            let salt = SaltString::encode_b64(&salt)
                .map_err(|_| anyhow!("failed to encode password salt"))?;
            let params = Params::new(65_536, 3, 1, Some(32))
                .map_err(|_| anyhow!("invalid Argon2id parameters"))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| anyhow!("failed to hash password"))
        }
        PasswordAlgorithm::Bcrypt => {
            ensure!(
                password.len() <= 72,
                "bcrypt passwords must not exceed 72 bytes"
            );
            bcrypt::non_truncating_hash(password, 12)
                .map_err(|_| anyhow!("failed to hash password"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_profiles_include_work_and_sizes_but_not_salt_or_digest_values() {
        let argon =
            "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";
        let bcrypt = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";

        let different_bcrypt =
            bcrypt::non_truncating_hash_with_salt("different-password", 4, [7; 16])
                .unwrap()
                .to_string();
        for (original, equivalent) in [
            (argon, argon.replace("m=256,t=2,p=1", "p=1,t=2,m=256")),
            (argon, argon.replace("c29tZXNhbHQ", "b3RoZXJzYWw")),
            (
                argon,
                argon.replace(
                    "nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ),
            ),
            (bcrypt, different_bcrypt),
            (bcrypt, bcrypt.replace("$2b$", "$2a$")),
            (bcrypt, bcrypt.replace("$2b$", "$2y$")),
        ] {
            let original = PasswordHash::parse(original).unwrap();
            let equivalent = PasswordHash::parse(&equivalent).unwrap();
            assert_ne!(original, equivalent);
            assert!(original.same_profile(&equivalent));
        }

        for (original, different) in [
            (argon, argon.replace("m=256", "m=512")),
            (argon, argon.replace("t=2", "t=3")),
            (argon, argon.replace("p=1", "p=2")),
            (argon, argon.replace("c29tZXNhbHQ", "c29tZXNhbHQx")),
            (
                argon,
                argon.replace(
                    "nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
                    "AAAAAAAAAAAAAAAAAAAAAA",
                ),
            ),
            (argon, argon.replace("p=1", "p=1,data=YWJj")),
            (bcrypt, bcrypt.replace("$04$", "$05$")),
            (argon, bcrypt.to_owned()),
        ] {
            assert!(
                !PasswordHash::parse(original)
                    .unwrap()
                    .same_profile(&PasswordHash::parse(&different).unwrap())
            );
        }
    }

    #[test]
    fn verifies_reference_hashes() {
        // Argon2 reference vectors and Python bcrypt.
        for (password, encoded) in [
            (
                "password",
                "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            ),
            (
                "correctbatteryhorsestapler",
                "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie",
            ),
        ] {
            let hash = PasswordHash::parse(encoded).unwrap();
            assert!(hash.verify(password));
            assert!(!hash.verify("incorrect-password"));
            assert!(!format!("{hash:?}").contains(encoded));
        }
    }

    #[test]
    fn accepts_bcrypt_versions_and_rejects_truncation() {
        let original = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
        for prefix in ["$2a$", "$2b$", "$2y$"] {
            let hash = PasswordHash::parse(&original.replacen("$2b$", prefix, 1)).unwrap();
            assert!(hash.verify("correctbatteryhorsestapler"));
            assert!(!hash.verify(&"x".repeat(73)));
        }
        assert!(generate_hash(&"x".repeat(73), PasswordAlgorithm::Bcrypt).is_err());
    }

    #[test]
    fn rejects_unsupported_malformed_and_excessive_hashes() {
        for encoded in [
            "plaintext",
            "$1$salt$hash",
            "$5$salt$hash",
            "$2x$04$......................YgIDy4hFBdVlc/6LHnD9mX488r9cLd2",
            "$argon2id$v=16$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            "$argon2id$v=19$m=262145,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            "$argon2id$v=19$m=256,t=11,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            "$argon2id$v=19$m=256,t=2,p=9$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ",
            "$argon2id$v=19$m=256,t=2,p=1$YQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
            "$2b$17$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie",
            "$6$bbe605c2cce4c642$BiBOywFAm9kdv6ZPpj2GaKVqeh/.c21pf1uFBaq.e59KEE2Ej74iJleXaLXURYV6uh5LF4K7dDc4vtRtPiiKB/",
            "$6$rounds=5000$bbe605c2cce4c642$BiBOywFAm9kdv6ZPpj2GaKVqeh/.c21pf1uFBaq.e59KEE2Ej74iJleXaLXURYV6uh5LF4K7dDc4vtRtPiiKB/",
        ] {
            assert!(PasswordHash::parse(encoded).is_err(), "{encoded}");
        }
    }

    #[test]
    fn validates_username_and_password_bytes() {
        for name in ["", "a:b", "a b", "é", "a\n"] {
            assert!(!valid_username(name));
        }
        assert!(valid_username("build-agent@example"));
        for password in ["", "line\nbreak", "nul\0"] {
            assert!(!valid_password(password));
        }
        assert!(valid_password("a:b:é"));
        assert!(!valid_password(&"x".repeat(1025)));
    }
}
