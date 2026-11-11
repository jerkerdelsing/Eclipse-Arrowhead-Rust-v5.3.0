// SPDX-License-Identifier: EPL-2.0
//! AH-GT-1 wire contract shared with Java SessionSecurity and Go session_security.
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use openssl::{
    asn1::Asn1Time,
    derive::Deriver,
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer, Verifier},
    ssl::SslFiletype,
    stack::Stack,
    symm::{Cipher, decrypt_aead, encrypt_aead},
    x509::{
        CrlStatus, X509, X509Crl, X509PurposeId, X509StoreContext,
        store::{X509Lookup, X509StoreBuilder},
        verify::X509VerifyFlags,
    },
};
use std::collections::BTreeSet;

pub const PROTOCOL: &str = "AH-GT-1";
const MAX_PLAIN: usize = 1_500_000;
fn refused() -> Error {
    Error::new(401, "AH-GT-1 authentication refused")
}
fn decode(text: &str) -> Result<Vec<u8>> {
    if text.len() > 2 * 1024 * 1024 {
        return Err(refused());
    }
    B64.decode(text).map_err(|_| refused())
}
pub struct Identity {
    key: PKey<Private>,
    pub chain: String,
    config: super::Config,
}
impl Identity {
    pub fn load(config: &super::Config, own_cn: &str) -> Result<Self> {
        let key = PKey::private_key_from_pem(&config::secret(&config.private_key)?)?;
        if key.id() != Id::RSA || key.bits() < 2048 {
            return Err(Error::bad("Relay signing key requires RSA >= 2048"));
        }
        let chain = std::fs::read_to_string(&config.certificate)?;
        let certs = X509::stack_from_pem(chain.as_bytes())?;
        if certs.len() != 2 || !certs[0].public_key()?.public_eq(&key) {
            return Err(Error::bad("Relay chain/key mismatch"));
        }
        let identity = Self {
            key,
            chain,
            config: config.clone(),
        };
        identity.verify_chain(&identity.chain, own_cn)?;
        Ok(identity)
    }
    fn verify_chain(&self, pem: &str, expected: &str) -> Result<X509> {
        if pem.len() > 32768 {
            return Err(refused());
        }
        let certs = X509::stack_from_pem(pem.as_bytes()).map_err(|_| refused())?;
        if certs.len() != 2
            || security::subject(&certs[0].to_der()?)? != (expected.to_owned(), "sy".into())
        {
            return Err(refused());
        }
        if !security::relay_certificate_constraints(&certs[0].to_der()?, &certs[1].to_der()?)? {
            return Err(refused());
        }
        // OpenSSL's path validation enforces critical directory-name constraints,
        // purpose, signatures, time, and CA/key usages. Only the configured trust
        // authority is loaded, never system roots or peer-supplied trust anchors.
        // Revocation (SOS-4, 2026-11-10): CRL_CHECK_ALL checks the relay certificate
        // against its cloud CA's CRL and the cross-certificate against the
        // organisation CA's CRL, so crlFiles must hold both. A missing, expired or
        // badly signed CRL fails the path, as in Java SessionSecurity and Go.
        let organisation = X509::from_pem(&std::fs::read(&self.config.ca)?)?;
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(organisation.clone())?;
        store.set_purpose(X509PurposeId::SSL_CLIENT)?;
        store.set_flags(X509VerifyFlags::CRL_CHECK | X509VerifyFlags::CRL_CHECK_ALL)?;
        let lookup = store.add_lookup(X509Lookup::file())?;
        let mut crls = Vec::new();
        for file in &self.config.crl_files {
            // PEM (one or more CRLs) or DER (one CRL)
            let raw = std::fs::read(file)?;
            let pem = raw.starts_with(b"-----BEGIN");
            crls.extend(parse_crls(&raw, pem)?);
            lookup.load_crl_file(
                file,
                if pem {
                    SslFiletype::PEM
                } else {
                    SslFiletype::ASN1
                },
            )?;
        }
        let mut untrusted = Stack::new()?;
        untrusted.push(certs[1].clone())?;
        let mut context = X509StoreContext::new()?;
        if !context.init(&store.build(), &certs[0], &untrusted, |ctx| {
            ctx.verify_cert()
        })? {
            return Err(refused());
        }
        // OpenSSL uses one CRL per issuer (the first of equal standing), so a
        // revoking CRL next to an older empty one could be missed: like Java and
        // Go, refuse when any current CRL signed by the issuer lists the serial.
        if revoked_by_any(&certs[0], &certs[1], &crls)?
            || revoked_by_any(&certs[1], &organisation, &crls)?
        {
            return Err(refused());
        }
        // End-entity public keys must be RSA for the mandatory PSS profile.
        if certs[0].public_key()?.id() != Id::RSA || security::ca_usages(&certs[0].to_der()?)? {
            return Err(refused());
        }
        Ok(certs[0].clone())
    }
    pub fn exchange(&self, role: &str, params: &Value) -> Result<Value> {
        let bytes = transcript(role, params)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)?;
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
        signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        signer.update(&bytes)?;
        Ok(
            json!({format!("{role}Key"): params[format!("{role}Key")], "signature":B64.encode(signer.sign_to_vec()?),"certificateChain":self.chain}),
        )
    }
    pub fn verify(
        &self,
        exchange: &Value,
        expected: &str,
        role: &str,
        params: &Value,
    ) -> Result<()> {
        let certificate = self.verify_chain(s(exchange, "certificateChain"), expected)?;
        let public = certificate.public_key()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &public)?;
        verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
        verifier.set_rsa_mgf1_md(MessageDigest::sha256())?;
        verifier.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        verifier.update(&transcript(role, params)?)?;
        if !verifier.verify(&decode(s(exchange, "signature"))?)? {
            return Err(refused());
        }
        Ok(())
    }
}
fn parse_crls(raw: &[u8], pem: bool) -> Result<Vec<X509Crl>> {
    if !pem {
        return Ok(vec![X509Crl::from_der(raw)?]);
    }
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for part in text.split("-----BEGIN X509 CRL-----").skip(1) {
        let block = format!("-----BEGIN X509 CRL-----{part}");
        out.push(X509Crl::from_pem(block.as_bytes())?);
    }
    Ok(out)
}
/// Whether a current CRL that `issuer` signed lists `cert`.
fn revoked_by_any(cert: &X509, issuer: &X509, crls: &[X509Crl]) -> Result<bool> {
    let now = Asn1Time::days_from_now(0)?;
    let name = issuer.subject_name().to_der()?;
    let key = issuer.public_key()?;
    for crl in crls {
        if crl.issuer_name().to_der()? != name || !crl.verify(&key).unwrap_or(false) {
            continue;
        }
        let current = crl.last_update() <= now && crl.next_update().is_some_and(|next| next >= now);
        if current && !matches!(crl.get_by_cert(cert), CrlStatus::NotRevoked) {
            return Ok(true);
        }
    }
    Ok(false)
}
pub fn transcript(role: &str, params: &Value) -> Result<Vec<u8>> {
    if !["provider", "consumer"].contains(&role) {
        return Err(refused());
    }
    let mut fields = vec![PROTOCOL.to_owned(), role.to_owned()];
    for name in [
        "sessionId",
        "consumer",
        "consumerCloud",
        "provider",
        "serviceDefinition",
        "consumerGateTunnel",
        "providerGateTunnel",
        "providerKey",
    ] {
        let value = s(params, name);
        if value.is_empty() || value.len() > 512 || value.contains(['\r', '\n', '\0']) {
            return Err(refused());
        }
        fields.push(value.into());
    }
    if role == "consumer" {
        let value = s(params, "consumerKey");
        if value.is_empty() || value.len() > 128 || value.contains(['\r', '\n', '\0']) {
            return Err(refused());
        }
        fields.push(value.into());
    }
    Ok(fields.join("\n").into_bytes())
}
pub fn ephemeral() -> Result<PKey<Private>> {
    Ok(PKey::generate_x25519()?)
}
pub fn public(key: &PKey<Private>) -> Result<String> {
    Ok(B64.encode(key.raw_public_key()?))
}
fn hmac(key: &[u8], content: &[u8]) -> Result<Vec<u8>> {
    let key = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(content)?;
    Ok(signer.sign_to_vec()?)
}
pub fn derive(own: &PKey<Private>, peer: &str, session: &str) -> Result<[Vec<u8>; 2]> {
    let raw = decode(peer)?;
    if raw.len() != 32 {
        return Err(refused());
    }
    let peer = PKey::public_key_from_raw_bytes(&raw, Id::X25519)?;
    let mut agreement = Deriver::new(own)?;
    agreement.set_peer(&peer)?;
    let shared = agreement.derive_to_vec()?;
    if shared.iter().all(|v| *v == 0) {
        return Err(refused());
    }
    let prk = hmac(session.as_bytes(), &shared)?;
    Ok([
        hmac(&prk, b"AH-GT-1 c2p\x01")?,
        hmac(&prk, b"AH-GT-1 p2c\x01")?,
    ])
}
fn aad(session: &str, direction: &str, seq: u64) -> Result<Vec<u8>> {
    if !["c2p", "p2c"].contains(&direction) || seq == 0 || seq > i64::MAX as u64 {
        return Err(refused());
    }
    Ok(format!("{PROTOCOL}|{session}|{direction}|{seq}").into_bytes())
}
pub fn seal(key: &[u8], session: &str, direction: &str, seq: u64, value: &Value) -> Result<Value> {
    if key.len() != 32 || !value.is_object() {
        return Err(refused());
    }
    let mut value = value.clone();
    value["timestamp"] = (chrono::Utc::now().timestamp_millis() as f64 / 1000.0).into();
    let plain = serde_json::to_vec(&value)?;
    if plain.len() > MAX_PLAIN {
        return Err(Error::new(413, "Tunnel content exceeds limit"));
    }
    let mut nonce = [0; 12];
    openssl::rand::rand_bytes(&mut nonce)?;
    let mut tag = [0; 16];
    let mut cipher = encrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        &aad(session, direction, seq)?,
        &plain,
        &mut tag,
    )?;
    cipher.extend_from_slice(&tag);
    Ok(json!({"seq":seq,"nonce":B64.encode(nonce),"ciphertext":B64.encode(cipher)}))
}
pub fn open(key: &[u8], session: &str, direction: &str, envelope: &Value) -> Result<(u64, Value)> {
    let seq = envelope["seq"].as_u64().ok_or_else(refused)?;
    let nonce = decode(s(envelope, "nonce"))?;
    let bytes = decode(s(envelope, "ciphertext"))?;
    if nonce.len() != 12 || bytes.len() < 16 || bytes.len() > MAX_PLAIN + 16 || key.len() != 32 {
        return Err(refused());
    }
    let at = bytes.len() - 16;
    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        &aad(session, direction, seq)?,
        &bytes[..at],
        &bytes[at..],
    )
    .map_err(|_| refused())?;
    let value: Value = serde_json::from_slice(&plain).map_err(|_| refused())?;
    let timestamp = value["timestamp"].as_f64().ok_or_else(refused)?;
    let now = chrono::Utc::now().timestamp_millis() as f64 / 1000.0;
    if !value.is_object() || !timestamp.is_finite() || (now - timestamp).abs() > 120.0 {
        return Err(refused());
    }
    Ok((seq, value))
}
#[derive(Default)]
pub struct Replay {
    highest: u64,
    seen: BTreeSet<u64>,
}
impl Replay {
    pub fn accept(&mut self, sequence: u64) -> bool {
        if sequence == 0
            || sequence > i64::MAX as u64
            || self.seen.contains(&sequence)
            || sequence <= self.highest.saturating_sub(4096)
        {
            return false;
        }
        self.highest = self.highest.max(sequence);
        self.seen.insert(sequence);
        self.seen = self
            .seen
            .split_off(&(self.highest.saturating_sub(4096) + 1));
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn derives_and_authenticates_the_java_go_reference_vector() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/ahgt1-reference-vector.json"
        ))
        .unwrap();
        let session = &vector["session"];
        let consumer = PKey::private_key_from_raw_bytes(
            &decode(s(&vector, "consumerEphemeralPrivate")).unwrap(),
            Id::X25519,
        )
        .unwrap();
        let keys = derive(
            &consumer,
            s(session, "providerKey"),
            s(session, "sessionId"),
        )
        .unwrap();
        assert_eq!(B64.encode(&keys[0]), vector["c2pKey"]);
        assert_eq!(B64.encode(&keys[1]), vector["p2cKey"]);
        for (which, direction, key) in [("request", "c2p", &keys[0]), ("reply", "p2c", &keys[1])] {
            let envelope = &vector[which];
            let bytes = decode(s(envelope, "ciphertext")).unwrap();
            let n = bytes.len() - 16;
            // The published reference vector has a historical timestamp. Verify
            // its AEAD/tag with the exact wire AAD; production open() separately
            // applies the mandatory fresh-message clock window.
            let plain = decrypt_aead(
                Cipher::aes_256_gcm(),
                key,
                Some(&decode(s(envelope, "nonce")).unwrap()),
                &aad(
                    s(session, "sessionId"),
                    direction,
                    envelope["seq"].as_u64().unwrap(),
                )
                .unwrap(),
                &bytes[..n],
                &bytes[n..],
            )
            .unwrap();
            let content: Value = serde_json::from_slice(&plain).unwrap();
            if which == "request" {
                assert_eq!(content["path"], "/datamanager/data-historian/put-data");
            } else {
                assert_eq!(content["status"], 201);
            }
        }
    }
    #[test]
    fn directional_key_agreement_and_aead_binding() {
        let a = ephemeral().unwrap();
        let b = ephemeral().unwrap();
        let keys = derive(&a, &public(&b).unwrap(), "session").unwrap();
        assert_eq!(keys, derive(&b, &public(&a).unwrap(), "session").unwrap());
        assert_ne!(keys[0], keys[1]);
        let sealed = seal(
            &keys[0],
            "session",
            "c2p",
            1,
            &json!({"method":"GET","path":"/sample"}),
        )
        .unwrap();
        assert_eq!(
            open(&keys[0], "session", "c2p", &sealed).unwrap().1["path"],
            "/sample"
        );
        for (id, dir, key) in [
            ("foreign", "c2p", &keys[0]),
            ("session", "p2c", &keys[0]),
            ("session", "c2p", &keys[1]),
        ] {
            assert!(open(key, id, dir, &sealed).is_err());
        }
        let mut tampered = sealed.clone();
        tampered["seq"] = 2.into();
        assert!(open(&keys[0], "session", "c2p", &tampered).is_err());
        assert!(derive(&a, &B64.encode([0; 32]), "session").is_err());
    }
    #[test]
    fn replay_window_and_transcript_separation() {
        let mut replay = Replay::default();
        assert!(!replay.accept(0));
        assert!(replay.accept(3));
        assert!(replay.accept(1));
        assert!(!replay.accept(3));
        assert!(replay.accept(5000));
        assert!(!replay.accept(2));
        let value = json!({"sessionId":"one","consumer":"Consumer","consumerCloud":"RustDev|Lab","provider":"Provider","serviceDefinition":"sample","consumerGateTunnel":"GateTunnel.RustDev.Lab.arrowhead.eu","providerGateTunnel":"GateTunnel.TestCloud.Company.arrowhead.eu","providerKey":"key","consumerKey":"key2"});
        let provider = String::from_utf8(transcript("provider", &value).unwrap()).unwrap();
        assert_eq!(
            provider,
            "AH-GT-1\nprovider\none\nConsumer\nRustDev|Lab\nProvider\nsample\nGateTunnel.RustDev.Lab.arrowhead.eu\nGateTunnel.TestCloud.Company.arrowhead.eu\nkey"
        );
        assert_ne!(
            transcript("provider", &value).unwrap(),
            transcript("consumer", &value).unwrap()
        );
        let mut injected = value;
        injected["consumer"] = "other\nfield".into();
        assert!(transcript("provider", &injected).is_err());
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ahgt1-revocation"
    );
    const PEER: &str = "GateTunnel.PeerCloud.Company.arrowhead.eu";

    /// SOS-4: the peer's own key exchange, verified with the given CRL files; None if accepted. Shared fixtures with
    /// the Java and Go tests (make_revocation.py, test keys only).
    fn verdict(crls: &[&str]) -> Option<String> {
        let dir = std::env::temp_dir().join(format!("ahgt1-revocation-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("peer-relay.key");
        std::fs::copy(format!("{FIXTURES}/peer-relay.key"), &key).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = super::super::Config {
            host: "relay".into(),
            port: 8883,
            relay_common_name: "relay".into(),
            certificate: format!("{FIXTURES}/peer-relay-chain.crt"),
            private_key: key.to_string_lossy().into(),
            ca: format!("{FIXTURES}/org-ca.crt"),
            crl_files: crls.iter().map(|c| format!("{FIXTURES}/{c}")).collect(),
            peers: Default::default(),
            foreign_targets: Vec::new(),
            min_port: 8200,
            max_port: 8299,
        };
        let identity = match Identity::load(&config, PEER) {
            Ok(identity) => identity,
            Err(e) => return Some(format!("load: {e:?}")),
        };
        let params = json!({"sessionId":"revocation","consumer":"c","consumerCloud":"C|O","provider":"p",
            "serviceDefinition":"s","consumerGateTunnel":"a","providerGateTunnel":"b","providerKey":"k"});
        let exchange = identity.exchange("provider", &params).unwrap();
        identity
            .verify(&exchange, PEER, "provider", &params)
            .err()
            .map(|e| format!("{e:?}"))
    }

    #[test]
    fn peer_chain_is_checked_against_the_cloud_and_organisation_crls() {
        assert_eq!(verdict(&["peer-ca.crl", "org-ca.crl"]), None);
        assert_eq!(
            verdict(&["peer-ca-expired.crl", "peer-ca.crl", "org-ca.crl"]),
            None
        );
        for refused in [
            // in both orders: OpenSSL alone would use only the first of the two
            &["peer-ca.crl", "peer-ca-revoked.crl", "org-ca.crl"][..],
            &["peer-ca-revoked.crl", "peer-ca.crl", "org-ca.crl"],
            &["peer-ca-revoked.crl", "org-ca.crl"],
            &["peer-ca.crl", "org-ca-revoked.crl"],
            &["org-ca.crl"],
            &["peer-ca.crl"],
            &["peer-ca-forged.crl", "org-ca.crl"],
            &["peer-ca-expired.crl", "org-ca.crl"],
        ] {
            assert!(verdict(refused).is_some(), "{refused:?} accepted");
        }
    }
}
