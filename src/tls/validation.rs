use std::collections::HashSet;

use anyhow::{Context, Result, anyhow, ensure};
use rcgen::{KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaValidity {
    pub root_not_before: OffsetDateTime,
    pub root_not_after: OffsetDateTime,
    pub intermediate_not_before: OffsetDateTime,
    pub intermediate_not_after: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientCertificateValidity {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

#[cfg(test)]
pub(crate) fn validate_ca_chain(
    root_der: &[u8],
    intermediate_der: &[u8],
    intermediate_key: &KeyPair,
    now: OffsetDateTime,
) -> Result<CaValidity> {
    validate_ca_hierarchy(&[intermediate_der, root_der], intermediate_key, now)
}

pub(crate) fn validate_ca_hierarchy(
    chain: &[&[u8]],
    intermediate_key: &KeyPair,
    now: OffsetDateTime,
) -> Result<CaValidity> {
    ensure!(
        chain.len() >= 2,
        "CA hierarchy must contain an intermediate and a trust anchor"
    );
    let certificates: Vec<_> = chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            let label = if index == 0 {
                "intermediate".to_string()
            } else if index + 1 == chain.len() {
                "root".to_string()
            } else {
                format!("parent CA {index}")
            };
            parse_certificate_exact(der, &label).map(|certificate| (label, certificate))
        })
        .collect::<Result<_>>()?;

    for (label, certificate) in &certificates {
        validate_extensions(certificate, label, false)?;
        validate_current_time(certificate, label, now)?;
    }

    let (intermediate_label, intermediate) = &certificates[0];
    validate_ca_extensions(intermediate, intermediate_label, Some(0), None)?;
    let key_spki = intermediate_key.subject_public_key_info();
    ensure!(
        intermediate.public_key().raw == key_spki.as_slice(),
        "intermediate key does not match certificate"
    );

    for parent_index in 1..certificates.len() {
        let (child_label, child) = &certificates[parent_index - 1];
        let (parent_label, parent) = &certificates[parent_index];
        validate_ca_extensions(parent, parent_label, None, Some(parent_index as u32))?;
        ensure!(
            child.issuer() == parent.subject(),
            "{child_label} issuer does not match {parent_label} subject"
        );
        child
            .verify_signature(Some(parent.public_key()))
            .map_err(|err| anyhow!("{child_label} signature verification failed: {err}"))?;
        ensure!(
            child.validity().not_after.to_datetime() <= parent.validity().not_after.to_datetime(),
            "{child_label} certificate expires after {parent_label} certificate"
        );
    }

    let intermediate_not_before = intermediate.validity().not_before.to_datetime();
    let intermediate_not_after = intermediate.validity().not_after.to_datetime();
    let (_, root) = certificates.last().expect("chain length checked");
    let root_not_before = root.validity().not_before.to_datetime();
    let root_not_after = root.validity().not_after.to_datetime();

    Ok(CaValidity {
        root_not_before,
        root_not_after,
        intermediate_not_before,
        intermediate_not_after,
    })
}

pub(crate) fn validate_client_certificate_chain(
    chain: &[&[u8]],
    key: &KeyPair,
    expected_common_name: &str,
    now: OffsetDateTime,
) -> Result<ClientCertificateValidity> {
    ensure!(
        chain.len() >= 2,
        "client certificate chain must contain a leaf and a trust anchor"
    );
    let certificates: Vec<_> = chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            let label = match index {
                0 => "client leaf".to_string(),
                index if index + 1 == chain.len() => "root".to_string(),
                _ => format!("parent CA {index}"),
            };
            parse_certificate_exact(der, &label).map(|certificate| (label, certificate))
        })
        .collect::<Result<_>>()?;

    for (index, (label, certificate)) in certificates.iter().enumerate() {
        validate_extensions(certificate, label, index == 0)?;
        validate_current_time(certificate, label, now)?;
    }

    let (leaf_label, leaf) = &certificates[0];
    ensure!(
        leaf.basic_constraints()
            .with_context(|| format!("invalid {leaf_label} basicConstraints extension"))?
            .is_none_or(|constraints| !constraints.value.ca),
        "{leaf_label} basicConstraints must not set CA=true"
    );
    let key_usage = leaf
        .key_usage()
        .with_context(|| format!("invalid {leaf_label} keyUsage extension"))?
        .ok_or_else(|| anyhow!("{leaf_label} certificate is missing keyUsage"))?;
    ensure!(
        key_usage.value.digital_signature(),
        "{leaf_label} keyUsage must include digitalSignature"
    );
    let extended_key_usage = leaf
        .extended_key_usage()
        .with_context(|| format!("invalid {leaf_label} extendedKeyUsage extension"))?
        .ok_or_else(|| anyhow!("{leaf_label} certificate is missing extendedKeyUsage"))?;
    let usage = extended_key_usage.value;
    ensure!(
        usage.client_auth
            && !usage.any
            && !usage.server_auth
            && !usage.code_signing
            && !usage.email_protection
            && !usage.time_stamping
            && !usage.ocsp_signing
            && usage.other.is_empty(),
        "{leaf_label} extendedKeyUsage must contain only clientAuth"
    );
    let common_names = leaf.subject().iter_common_name().collect::<Vec<_>>();
    ensure!(
        common_names.len() == 1 && common_names[0].as_str().ok() == Some(expected_common_name),
        "{leaf_label} common name does not match the configured identity"
    );
    ensure!(
        leaf.public_key().raw == key.subject_public_key_info().as_slice(),
        "client private key does not match certificate"
    );

    for parent_index in 1..certificates.len() {
        let (child_label, child) = &certificates[parent_index - 1];
        let (parent_label, parent) = &certificates[parent_index];
        validate_ca_extensions(parent, parent_label, None, Some((parent_index - 1) as u32))?;
        ensure!(
            child.issuer() == parent.subject(),
            "{child_label} issuer does not match {parent_label} subject"
        );
        child
            .verify_signature(Some(parent.public_key()))
            .map_err(|err| anyhow!("{child_label} signature verification failed: {err}"))?;
        ensure!(
            child.validity().not_after.to_datetime() <= parent.validity().not_after.to_datetime(),
            "{child_label} certificate expires after {parent_label} certificate"
        );
    }

    Ok(ClientCertificateValidity {
        not_before: leaf.validity().not_before.to_datetime(),
        not_after: leaf.validity().not_after.to_datetime(),
    })
}

pub(crate) fn parse_strict_certificate_pem_bundle(
    bytes: &[u8],
    label: &str,
) -> Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let text =
        std::str::from_utf8(bytes).with_context(|| format!("{label} is not valid UTF-8 PEM"))?;
    let mut certificates = Vec::new();
    let mut block: Option<String> = None;

    for (line_index, raw_line) in text.lines().enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        match &mut block {
            Some(pem) if line == END => {
                pem.push_str(END);
                pem.push('\n');
                let certificate = CertificateDer::from_pem_slice(pem.as_bytes())
                    .with_context(|| format!("failed to parse certificate in {label}"))?;
                certificates.push(certificate.as_ref().to_vec());
                block = None;
            }
            Some(pem) => {
                ensure!(
                    !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "),
                    "{label} contains an unexpected PEM boundary on line {}",
                    line_index + 1
                );
                pem.push_str(line);
                pem.push('\n');
            }
            None if line.trim().is_empty() => {}
            None if line == BEGIN => {
                let mut pem = String::from(BEGIN);
                pem.push('\n');
                block = Some(pem);
            }
            None => {
                ensure!(
                    false,
                    "{label} contains non-certificate data on line {}",
                    line_index + 1
                );
            }
        }
    }
    ensure!(
        block.is_none(),
        "{label} contains an unterminated certificate"
    );
    ensure!(!certificates.is_empty(), "{label} contains no certificates");
    Ok(certificates)
}

fn parse_certificate_exact<'a>(der: &'a [u8], label: &str) -> Result<X509Certificate<'a>> {
    let (remaining, certificate) = parse_x509_certificate(der)
        .map_err(|err| anyhow!("failed to parse {label} certificate DER: {err}"))?;
    ensure!(
        remaining.is_empty(),
        "{label} certificate DER contains trailing data"
    );
    Ok(certificate)
}

fn validate_extensions(
    certificate: &X509Certificate<'_>,
    label: &str,
    allow_critical_extended_key_usage: bool,
) -> Result<()> {
    let mut extension_oids = HashSet::new();
    for extension in certificate.extensions() {
        let parsed = extension.parsed_extension();
        ensure!(
            extension_oids.insert(extension.oid.clone()),
            "{label} certificate contains duplicate extension {}",
            extension.oid
        );
        ensure!(
            !matches!(
                parsed,
                ParsedExtension::ParseError { .. } | ParsedExtension::Unparsed
            ),
            "{label} certificate contains malformed extension {}",
            extension.oid
        );
        ensure!(
            !matches!(parsed, ParsedExtension::NameConstraints(_)),
            "{label} certificate contains unsupported nameConstraints"
        );
        ensure!(
            !extension.critical
                || matches!(
                    parsed,
                    ParsedExtension::BasicConstraints(_) | ParsedExtension::KeyUsage(_)
                )
                || allow_critical_extended_key_usage
                    && matches!(parsed, ParsedExtension::ExtendedKeyUsage(_)),
            "{label} certificate contains unsupported critical extension {}",
            extension.oid
        );
    }
    Ok(())
}

fn validate_current_time(
    certificate: &X509Certificate<'_>,
    label: &str,
    now: OffsetDateTime,
) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let not_before = certificate.validity().not_before.to_datetime();
    let not_after = certificate.validity().not_after.to_datetime();
    ensure!(
        now >= not_before,
        "{label} certificate is not yet valid (not before {not_before})"
    );
    ensure!(
        now <= not_after,
        "{label} certificate has expired (not after {not_after})"
    );
    Ok((not_before, not_after))
}

fn validate_ca_extensions(
    certificate: &X509Certificate<'_>,
    label: &str,
    required_path_len: Option<u32>,
    minimum_path_len: Option<u32>,
) -> Result<()> {
    let basic_constraints = certificate
        .basic_constraints()
        .with_context(|| format!("invalid {label} basicConstraints extension"))?
        .ok_or_else(|| anyhow!("{label} certificate is missing basicConstraints"))?;
    ensure!(
        basic_constraints.value.ca,
        "{label} basicConstraints must set CA=true"
    );
    if let Some(required_path_len) = required_path_len {
        ensure!(
            basic_constraints.value.path_len_constraint == Some(required_path_len),
            "{label} basicConstraints pathLenConstraint must be exactly {required_path_len}"
        );
    }
    if let Some(minimum_path_len) = minimum_path_len {
        ensure!(
            basic_constraints
                .value
                .path_len_constraint
                .is_none_or(|path_len| path_len >= minimum_path_len),
            "{label} basicConstraints pathLenConstraint must permit an intermediate CA"
        );
    }

    let key_usage = certificate
        .key_usage()
        .with_context(|| format!("invalid {label} keyUsage extension"))?
        .ok_or_else(|| anyhow!("{label} certificate is missing keyUsage"))?;
    ensure!(
        key_usage.value.key_cert_sign(),
        "{label} keyUsage must include keyCertSign"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName,
        DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyUsagePurpose, NameConstraints,
        PKCS_ECDSA_P256_SHA256,
    };
    use time::Duration;

    struct TestChain {
        root_der: Vec<u8>,
        intermediate_der: Vec<u8>,
        intermediate_key: KeyPair,
    }

    fn validation_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid test timestamp")
    }

    fn ca_params(
        common_name: &str,
        is_ca: IsCa,
        key_usages: Vec<KeyUsagePurpose>,
    ) -> CertificateParams {
        let now = validation_time();
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);
        let mut params = CertificateParams::default();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(30);
        params.distinguished_name = distinguished_name;
        params.is_ca = is_ca;
        params.key_usages = key_usages;
        params
    }

    fn root_params(common_name: &str) -> CertificateParams {
        ca_params(
            common_name,
            IsCa::Ca(BasicConstraints::Constrained(1)),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        )
    }

    fn intermediate_params() -> CertificateParams {
        ca_params(
            "Test Intermediate",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        )
    }

    fn client_params(common_name: &str) -> CertificateParams {
        let mut params = ca_params(
            common_name,
            IsCa::NoCa,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params
    }

    fn critical_client_auth_extension() -> CustomExtension {
        let mut extension = CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            vec![
                0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
            ],
        );
        extension.set_criticality(true);
        extension
    }

    fn generate_client_chain(client_params: CertificateParams) -> Result<(Vec<Vec<u8>>, KeyPair)> {
        let root_params = root_params("Test Root");
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let root = root_params.self_signed(&root_key)?;
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);

        let intermediate_params = intermediate_params();
        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let intermediate = intermediate_params.signed_by(&intermediate_key, &root_issuer)?;
        let intermediate_issuer =
            rcgen::Issuer::from_params(&intermediate_params, &intermediate_key);

        let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let client = client_params.signed_by(&client_key, &intermediate_issuer)?;
        Ok((
            vec![
                client.der().as_ref().to_vec(),
                intermediate.der().as_ref().to_vec(),
                root.der().as_ref().to_vec(),
            ],
            client_key,
        ))
    }

    #[test]
    fn validates_client_certificate_identity_key_usage_and_chain() -> Result<()> {
        let (chain, key) = generate_client_chain(client_params("exfilguard-production"))?;
        let chain_refs = chain.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let validity = validate_client_certificate_chain(
            &chain_refs,
            &key,
            "exfilguard-production",
            validation_time(),
        )?;
        assert!(validity.not_before < validity.not_after);

        assert!(
            validate_client_certificate_chain(
                &chain_refs,
                &key,
                "different-identity",
                validation_time(),
            )
            .is_err()
        );
        let wrong_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        assert!(
            validate_client_certificate_chain(
                &chain_refs,
                &wrong_key,
                "exfilguard-production",
                validation_time(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_client_certificate_without_client_only_usage() -> Result<()> {
        let mut params = client_params("exfilguard-production");
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let (chain, key) = generate_client_chain(params)?;
        let chain_refs = chain.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(
            validate_client_certificate_chain(
                &chain_refs,
                &key,
                "exfilguard-production",
                validation_time(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn accepts_critical_client_auth_on_client_leaf_only() -> Result<()> {
        let mut params = client_params("exfilguard-production");
        params.extended_key_usages.clear();
        params
            .custom_extensions
            .push(critical_client_auth_extension());
        let (chain, key) = generate_client_chain(params)?;
        let chain_refs = chain.iter().map(Vec::as_slice).collect::<Vec<_>>();
        validate_client_certificate_chain(
            &chain_refs,
            &key,
            "exfilguard-production",
            validation_time(),
        )?;

        let mut intermediate = intermediate_params();
        intermediate
            .custom_extensions
            .push(critical_client_auth_extension());
        let chain = generate_chain(root_params("Test Root"), intermediate)?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    fn generate_chain(
        root_params: CertificateParams,
        intermediate_params: CertificateParams,
    ) -> Result<TestChain> {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let root_cert = root_params.self_signed(&root_key)?;
        generate_intermediate(root_params, root_key, root_cert, intermediate_params)
    }

    fn generate_intermediate(
        root_params: CertificateParams,
        root_key: KeyPair,
        root_cert: Certificate,
        intermediate_params: CertificateParams,
    ) -> Result<TestChain> {
        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let intermediate_cert = intermediate_params.signed_by(&intermediate_key, &root_issuer)?;
        Ok(TestChain {
            root_der: root_cert.der().as_ref().to_vec(),
            intermediate_der: intermediate_cert.der().as_ref().to_vec(),
            intermediate_key,
        })
    }

    fn valid_chain() -> Result<TestChain> {
        generate_chain(root_params("Test Root"), intermediate_params())
    }

    fn validate(chain: &TestChain) -> Result<CaValidity> {
        validate_ca_chain(
            &chain.root_der,
            &chain.intermediate_der,
            &chain.intermediate_key,
            validation_time(),
        )
    }

    #[test]
    fn accepts_valid_chain_and_returns_validity() -> Result<()> {
        let chain = valid_chain()?;
        let validity = validate(&chain)?;

        assert_eq!(
            validity.root_not_before,
            validation_time() - Duration::days(1)
        );
        assert_eq!(
            validity.root_not_after,
            validation_time() + Duration::days(30)
        );
        assert_eq!(
            validity.intermediate_not_before,
            validation_time() - Duration::days(1)
        );
        assert_eq!(
            validity.intermediate_not_after,
            validation_time() + Duration::days(30)
        );
        Ok(())
    }

    #[test]
    fn accepts_non_self_signed_root_trust_anchor() -> Result<()> {
        let parent_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let parent_params = root_params("Parent Root");
        let parent_issuer = rcgen::Issuer::from_params(&parent_params, &parent_key);

        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let root_params = root_params("Configured Trust Anchor");
        let root_cert = root_params.signed_by(&root_key, &parent_issuer)?;
        let chain = generate_intermediate(root_params, root_key, root_cert, intermediate_params())?;

        validate(&chain)?;
        Ok(())
    }

    #[test]
    fn accepts_and_validates_a_multi_level_ca_hierarchy() -> Result<()> {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut root_params = root_params("Test Root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(2));
        let root_cert = root_params.self_signed(&root_key)?;
        let root_issuer = rcgen::Issuer::from_params(&root_params, &root_key);

        let signer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut signer_params = ca_params(
            "Vault Signing Issuer",
            IsCa::Ca(BasicConstraints::Constrained(1)),
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
        );
        signer_params.use_authority_key_identifier_extension = true;
        let signer_cert = signer_params.signed_by(&signer_key, &root_issuer)?;
        let signer_issuer = rcgen::Issuer::from_params(&signer_params, &signer_key);

        let intermediate_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let intermediate_cert =
            intermediate_params().signed_by(&intermediate_key, &signer_issuer)?;
        let chain = [
            intermediate_cert.der().as_ref(),
            signer_cert.der().as_ref(),
            root_cert.der().as_ref(),
        ];
        validate_ca_hierarchy(&chain, &intermediate_key, validation_time())?;
        Ok(())
    }

    #[test]
    fn rejects_unrelated_root_even_with_same_subject() -> Result<()> {
        let chain = valid_chain()?;
        let unrelated_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let unrelated_root = root_params("Test Root").self_signed(&unrelated_key)?;

        assert!(
            validate_ca_chain(
                unrelated_root.der().as_ref(),
                &chain.intermediate_der,
                &chain.intermediate_key,
                validation_time(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_intermediate_issuer_name_mismatch() -> Result<()> {
        let chain = valid_chain()?;
        let unrelated_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let unrelated_root = root_params("Different Root").self_signed(&unrelated_key)?;

        assert!(
            validate_ca_chain(
                unrelated_root.der().as_ref(),
                &chain.intermediate_der,
                &chain.intermediate_key,
                validation_time(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_non_ca_root_and_intermediate() -> Result<()> {
        let non_ca_root = ca_params("Test Root", IsCa::NoCa, vec![KeyUsagePurpose::KeyCertSign]);
        assert!(
            generate_chain(non_ca_root, intermediate_params())
                .and_then(|c| validate(&c))
                .is_err()
        );

        let non_ca_intermediate = ca_params(
            "Test Intermediate",
            IsCa::NoCa,
            vec![KeyUsagePurpose::KeyCertSign],
        );
        assert!(
            generate_chain(root_params("Test Root"), non_ca_intermediate)
                .and_then(|c| validate(&c))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_intermediate_path_len() -> Result<()> {
        let wrong_path_len = ca_params(
            "Test Intermediate",
            IsCa::Ca(BasicConstraints::Constrained(1)),
            vec![KeyUsagePurpose::KeyCertSign],
        );
        let chain = generate_chain(root_params("Test Root"), wrong_path_len)?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    #[test]
    fn rejects_root_path_len_that_forbids_an_intermediate() -> Result<()> {
        let root = ca_params(
            "Test Root",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            vec![KeyUsagePurpose::KeyCertSign],
        );
        let chain = generate_chain(root, intermediate_params())?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    #[test]
    fn strict_pem_bundle_rejects_keys_and_non_pem_data() -> Result<()> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let certificate = root_params("PEM Root").self_signed(&key)?.pem();
        let bundle = format!("{certificate}\n{certificate}");
        assert_eq!(
            parse_strict_certificate_pem_bundle(bundle.as_bytes(), "bundle")?.len(),
            2
        );

        let with_key = format!("{certificate}\n{}", key.serialize_pem());
        assert!(parse_strict_certificate_pem_bundle(with_key.as_bytes(), "bundle").is_err());
        let with_garbage = format!("{certificate}\nnot a certificate");
        assert!(parse_strict_certificate_pem_bundle(with_garbage.as_bytes(), "bundle").is_err());
        Ok(())
    }

    #[test]
    fn rejects_missing_and_wrong_key_usage() -> Result<()> {
        let missing_root_key_usage = ca_params(
            "Test Root",
            IsCa::Ca(BasicConstraints::Constrained(1)),
            Vec::new(),
        );
        let chain = generate_chain(missing_root_key_usage, intermediate_params())?;
        assert!(validate(&chain).is_err());

        let wrong_root_key_usage = ca_params(
            "Test Root",
            IsCa::Ca(BasicConstraints::Constrained(1)),
            vec![KeyUsagePurpose::DigitalSignature],
        );
        let chain = generate_chain(wrong_root_key_usage, intermediate_params())?;
        assert!(validate(&chain).is_err());

        let missing_key_usage = ca_params(
            "Test Intermediate",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            Vec::new(),
        );
        let chain = generate_chain(root_params("Test Root"), missing_key_usage)?;
        assert!(validate(&chain).is_err());

        let wrong_key_usage = ca_params(
            "Test Intermediate",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            vec![KeyUsagePurpose::DigitalSignature],
        );
        let chain = generate_chain(root_params("Test Root"), wrong_key_usage)?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    #[test]
    fn rejects_expired_and_not_yet_valid_certificates() -> Result<()> {
        let now = validation_time();
        let mut expired_root = root_params("Test Root");
        expired_root.not_before = now - Duration::days(2);
        expired_root.not_after = now - Duration::days(1);
        let chain = generate_chain(expired_root, intermediate_params())?;
        assert!(validate(&chain).is_err());

        let mut future_intermediate = intermediate_params();
        future_intermediate.not_before = now + Duration::days(1);
        future_intermediate.not_after = now + Duration::days(2);
        let chain = generate_chain(root_params("Test Root"), future_intermediate)?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    #[test]
    fn rejects_intermediate_key_mismatch() -> Result<()> {
        let chain = valid_chain()?;
        let wrong_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        assert!(
            validate_ca_chain(
                &chain.root_der,
                &chain.intermediate_der,
                &wrong_key,
                validation_time(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_intermediate_that_outlives_root() -> Result<()> {
        let now = validation_time();
        let mut root = root_params("Test Root");
        root.not_after = now + Duration::days(1);
        let mut intermediate = intermediate_params();
        intermediate.not_after = now + Duration::days(2);
        let chain = generate_chain(root, intermediate)?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    #[test]
    fn rejects_trailing_der_data() -> Result<()> {
        let chain = valid_chain()?;

        let mut root_with_trailing_data = chain.root_der.clone();
        root_with_trailing_data.push(0);
        assert!(
            validate_ca_chain(
                &root_with_trailing_data,
                &chain.intermediate_der,
                &chain.intermediate_key,
                validation_time(),
            )
            .is_err()
        );

        let mut intermediate_with_trailing_data = chain.intermediate_der.clone();
        intermediate_with_trailing_data.push(0);
        assert!(
            validate_ca_chain(
                &chain.root_der,
                &intermediate_with_trailing_data,
                &chain.intermediate_key,
                validation_time(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_duplicate_extensions() -> Result<()> {
        let mut root = root_params("Test Root");
        root.custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 19],
                vec![0x30, 0x03, 0x01, 0x01, 0xff],
            ));
        let chain = generate_chain(root, intermediate_params())?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    #[test]
    fn rejects_malformed_extensions() -> Result<()> {
        let mut malformed_root =
            ca_params("Test Root", IsCa::NoCa, vec![KeyUsagePurpose::KeyCertSign]);
        malformed_root
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 19],
                vec![0xff],
            ));
        let chain = generate_chain(malformed_root, intermediate_params())?;
        assert!(validate(&chain).is_err());
        Ok(())
    }

    #[test]
    fn rejects_name_constrained_ca_hierarchy() -> Result<()> {
        let mut root = root_params("Constrained Root");
        root.name_constraints = Some(NameConstraints {
            permitted_subtrees: vec![GeneralSubtree::DnsName(".corp.example".to_string())],
            excluded_subtrees: Vec::new(),
        });
        let chain = generate_chain(root, intermediate_params())?;

        let error = validate(&chain).unwrap_err();
        assert!(error.to_string().contains("unsupported nameConstraints"));
        Ok(())
    }

    #[test]
    fn rejects_only_critical_unknown_extensions() -> Result<()> {
        fn private_extension(critical: bool) -> CustomExtension {
            let mut extension =
                CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 55_555, 1], vec![5, 0]);
            extension.set_criticality(critical);
            extension
        }

        let mut critical_root = root_params("Critical Extension Root");
        critical_root
            .custom_extensions
            .push(private_extension(true));
        let critical_chain = generate_chain(critical_root, intermediate_params())?;
        let error = validate(&critical_chain).unwrap_err();
        assert!(error.to_string().contains("unsupported critical extension"));

        let mut noncritical_root = root_params("Noncritical Extension Root");
        noncritical_root
            .custom_extensions
            .push(private_extension(false));
        let noncritical_chain = generate_chain(noncritical_root, intermediate_params())?;
        validate(&noncritical_chain)?;
        Ok(())
    }
}
