use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

use anyhow::Result;
use argon2::password_hash::PasswordVerifier;

fn command(input: &[u8], arguments: &[&str]) -> Result<Output> {
    let mut process = Command::new(env!("CARGO_BIN_EXE_exfilguard"))
        .args([
            "--config",
            "/nonexistent/exfilguard.toml",
            "password-hash",
            "--stdin",
        ])
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    process.stdin.take().unwrap().write_all(input)?;
    Ok(process.wait_with_output()?)
}

#[test]
fn generates_supported_hashes_without_loading_configuration() -> Result<()> {
    let password = "cli-test-password";
    for algorithm in ["argon2id", "bcrypt", "sha512-crypt"] {
        let output = command(
            format!("{password}\n").as_bytes(),
            &["--algorithm", algorithm],
        )?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout)?;
        assert_eq!(stdout.lines().count(), 1);
        let hash = stdout.trim_end();
        exfilguard::authentication::PasswordHash::parse(hash)?;
        match algorithm {
            "argon2id" => {
                assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
                argon2::Argon2::default()
                    .verify_password(
                        password.as_bytes(),
                        &argon2::PasswordHash::new(hash).unwrap(),
                    )
                    .unwrap();
            }
            "bcrypt" => {
                assert!(hash.starts_with("$2b$12$"));
                assert!(bcrypt::non_truncating_verify(password, hash)?);
            }
            _ => {
                assert!(hash.starts_with("$6$rounds=100000$"));
                sha_crypt::sha512_check(password, hash).unwrap();
            }
        }
    }
    // The default algorithm uses a new salt for each invocation.
    let first = command(b"cli-test-password", &[])?;
    let second = command(b"cli-test-password\r\n", &[])?;
    assert!(first.status.success() && second.status.success());
    assert!(first.stdout.starts_with(b"$argon2id$"));
    assert_ne!(first.stdout, second.stdout);
    Ok(())
}

#[test]
fn rejects_invalid_input_without_printing_passwords() -> Result<()> {
    for input in [
        b"".as_slice(),
        b"\n",
        b"secret\nextra\n",
        b"secret\0",
        b"\xff",
        &vec![b'x'; 1025],
    ] {
        let output = command(input, &[])?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
    }
    let output = command(&[b'x'; 73], &["--algorithm", "bcrypt"])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let output = command(b"secret", &["--password", "secret"])?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    Ok(())
}
