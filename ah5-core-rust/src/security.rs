// SPDX-License-Identifier: EPL-2.0
use crate::{App, Config, Error, Principal, Result, config::secret, expired, s, valid_name};
use rustls::{
    RootCertStore,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{
        CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
        pem::PemObject,
    },
    server::WebPkiClientVerifier,
};
use serde_json::{Value, json};
use std::{fs, sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Material {
    name: String,
    suffix: String,
    certificate: String,
    private_key: String,
    ca: String,
    crl: Option<String>,
}
impl Material {
    fn fingerprint(&self) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        for path in [
            Some(&self.certificate),
            Some(&self.private_key),
            Some(&self.ca),
            self.crl.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            let bytes = fs::read(path)?;
            if bytes.len() > 1024 * 1024 {
                return Err(Error::bad("TLS material exceeds size limit"));
            }
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Ok(hash.finalize().to_vec())
    }
}
struct Reload {
    material: Material,
    current: std::sync::Mutex<(Vec<u8>, Tls)>,
}

#[derive(Clone)]
pub struct Tls {
    pub server: Arc<rustls::ServerConfig>,
    reload: Option<Arc<Reload>>,
    certificates: Vec<CertificateDer<'static>>,
    key: Arc<PrivateKeyDer<'static>>,
    verifier: Arc<dyn ServerCertVerifier>,
}
impl Tls {
    pub fn load(config: &Config) -> Result<Self> {
        Self::load_identity(
            &config.name,
            &config.cloud_suffix,
            &config.certificate,
            &config.private_key,
            &config.ca,
            config.crl_file.as_deref(),
        )
    }
    pub fn load_identity(
        system_name: &str,
        suffix: &str,
        certificate: &str,
        private_key: &str,
        ca: &str,
        crl_file: Option<&str>,
    ) -> Result<Self> {
        let material = Material {
            name: system_name.into(),
            suffix: suffix.into(),
            certificate: certificate.into(),
            private_key: private_key.into(),
            ca: ca.into(),
            crl: crl_file.map(String::from),
        };
        let before = material.fingerprint()?;
        let tls = Self::load_material(&material)?;
        if material.fingerprint()? != before {
            return Err(Error::bad("TLS material changed while loading"));
        }
        let reload = Reload {
            material,
            current: std::sync::Mutex::new((before, tls.clone())),
        };
        Ok(Self {
            reload: Some(Arc::new(reload)),
            ..tls
        })
    }
    fn load_material(material: &Material) -> Result<Self> {
        let Material {
            name: system_name,
            suffix,
            certificate,
            private_key,
            ca,
            crl,
        } = material;
        let crl_file = crl.as_deref();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certificates = CertificateDer::pem_slice_iter(&fs::read(certificate)?)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::bad("Invalid certificate PEM"))?;
        let key = PrivateKeyDer::from_pem_slice(&secret(private_key)?)
            .map_err(|_| Error::bad("Invalid private key PEM"))?;
        let leaf = certificates
            .first()
            .ok_or_else(|| Error::bad("Empty certificate chain"))?;
        let (name, profile) = subject(leaf.as_ref())?;
        if name != format!("{system_name}.{suffix}") || profile != "sy" {
            return Err(Error::bad(
                "Server certificate CN/profile does not match system",
            ));
        }
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&fs::read(ca)?) {
            roots
                .add(cert.map_err(|_| Error::bad("Invalid CA PEM"))?)
                .map_err(|_| Error::bad("Invalid trust anchor"))?
        }
        if roots.is_empty() {
            return Err(Error::bad("Trust bundle is empty"));
        }
        let roots = Arc::new(roots);
        let mut clients =
            WebPkiClientVerifier::builder_with_provider(roots.clone(), provider.clone());
        let mut servers = WebPkiServerVerifier::builder_with_provider(roots, provider.clone());
        if let Some(path) = crl_file {
            let crls = CertificateRevocationListDer::pem_slice_iter(&fs::read(path)?)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::bad("Invalid CRL PEM"))?;
            if crls.is_empty() {
                return Err(Error::bad("Empty CRL bundle"));
            };
            clients = clients
                .with_crls(crls.clone())
                .only_check_end_entity_revocation()
                .enforce_revocation_expiration();
            servers = servers
                .with_crls(crls)
                .only_check_end_entity_revocation()
                .enforce_revocation_expiration()
        }
        let verifier = servers
            .build()
            .map_err(|_| Error::bad("Invalid server verifier"))?;
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::bad("TLS configuration"))?
            .with_client_cert_verifier(
                clients
                    .build()
                    .map_err(|_| Error::bad("Invalid client verifier"))?,
            )
            .with_single_cert(certificates.clone(), key.clone_key())
            .map_err(|_| Error::bad("Certificate/private key mismatch"))?;
        // A resumed session must not bypass newly published revocations.
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.send_tls13_tickets = 0;
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            server: Arc::new(server),
            reload: None,
            certificates,
            key: Arc::new(key),
            verifier,
        })
    }
    /// Reload all TLS material as one validated snapshot. Invalid changes fail closed.
    fn refreshed(&self) -> Result<Self> {
        let Some(reload) = &self.reload else {
            return Ok(self.clone());
        };
        let mut current = reload
            .current
            .lock()
            .map_err(|_| Error::bad("TLS reload lock poisoned"))?;
        let before = reload.material.fingerprint()?;
        if before != current.0 {
            let fresh = Self::load_material(&reload.material)?;
            if reload.material.fingerprint()? != before {
                return Err(Error::bad("TLS material changed while loading"));
            }
            *current = (before, fresh);
        }
        Ok(current.1.clone())
    }
    pub fn server_current(&self) -> Result<Arc<rustls::ServerConfig>> {
        Ok(self.refreshed()?.server)
    }
    pub fn console_current(&self) -> Result<Arc<rustls::ServerConfig>> {
        let fresh = self.refreshed()?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::bad("TLS protocols"))?
        .with_no_client_auth()
        .with_single_cert(fresh.certificates, fresh.key.clone_key())
        .map_err(|_| Error::bad("Console certificate configuration"))?;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Arc::new(config))
    }
    pub fn client(&self, expected: &str) -> Result<reqwest::Client> {
        self.refreshed()?.client_current(expected)
    }
    pub fn client_config(&self, expected: &str) -> Result<rustls::ClientConfig> {
        self.refreshed()?.config_current(expected)
    }
    fn config_current(&self, expected: &str) -> Result<rustls::ClientConfig> {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::bad("TLS protocols"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            inner: self.verifier.clone(),
            expected: expected.into(),
        }))
        .with_client_auth_cert(self.certificates.clone(), self.key.clone_key())
        .map_err(|_| Error::bad("Client certificate configuration"))?;
        tls.resumption = rustls::client::Resumption::disabled();
        Ok(tls)
    }
    fn client_current(&self, expected: &str) -> Result<reqwest::Client> {
        let mut tls = self.config_current(expected)?;
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| Error::new(500, "HTTP client configuration failed"))
    }
}
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    expected: String,
}
impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_server_cert(end, intermediates, name, ocsp, now)?;
        let (cn, profile) = subject(end.as_ref())
            .map_err(|_| rustls::Error::General("Malformed authority identity".into()))?;
        if cn != self.expected || profile != "sy" {
            return Err(rustls::Error::General(
                "Unexpected authority CN/profile".into(),
            ));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// Minimal strict DER traversal only for subject identity attributes. Rustls/webpki
// performs chain, signature, time, usage and SAN validation before these values are trusted.
fn tlv<'a>(input: &mut &'a [u8]) -> Result<(u8, &'a [u8])> {
    if input.len() < 2 {
        return Err(Error::bad("Truncated DER"));
    }
    let tag = input[0];
    let first = input[1];
    let mut header = 2;
    let length = if first < 128 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > 4 || input.len() < 2 + count || input[2] == 0 {
            return Err(Error::bad("Invalid DER length"));
        }
        header += count;
        let mut n = 0usize;
        for b in &input[2..header] {
            n = n
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*b)))
                .ok_or_else(|| Error::bad("DER length overflow"))?
        }
        if n < 128 {
            return Err(Error::bad("Noncanonical DER length"));
        }
        n
    };
    let end = header
        .checked_add(length)
        .filter(|n| *n <= input.len())
        .ok_or_else(|| Error::bad("Truncated DER value"))?;
    let value = &input[header..end];
    *input = &input[end..];
    Ok((tag, value))
}
fn tagged<'a>(input: &mut &'a [u8], expected: u8) -> Result<&'a [u8]> {
    let (t, b) = tlv(input)?;
    if t != expected {
        return Err(Error::bad("Unexpected DER tag"));
    }
    Ok(b)
}
pub fn subject(cert: &[u8]) -> Result<(String, String)> {
    let mut outer = cert;
    let mut sequence = tagged(&mut outer, 0x30)?;
    if !outer.is_empty() {
        return Err(Error::bad("Trailing certificate data"));
    }
    let mut tbs = tagged(&mut sequence, 0x30)?;
    if tbs.first() == Some(&0xa0) {
        tlv(&mut tbs)?;
    }
    tagged(&mut tbs, 0x02)?;
    tagged(&mut tbs, 0x30)?;
    tagged(&mut tbs, 0x30)?;
    tagged(&mut tbs, 0x30)?;
    let mut name = tagged(&mut tbs, 0x30)?;
    let mut cn = None;
    let mut profile = None;
    while !name.is_empty() {
        let mut set = tagged(&mut name, 0x31)?;
        while !set.is_empty() {
            let mut attr = tagged(&mut set, 0x30)?;
            let oid = tagged(&mut attr, 0x06)?;
            let (tag, value) = tlv(&mut attr)?;
            if !attr.is_empty() {
                return Err(Error::bad("Invalid subject attribute"));
            };
            if oid == [0x55, 0x04, 0x03] || oid == [0x55, 0x04, 0x2e] {
                if ![0x0c, 0x13, 0x16].contains(&tag) {
                    return Err(Error::bad("Unsupported identity string"));
                }
                let text = std::str::from_utf8(value)
                    .map_err(|_| Error::bad("Invalid identity string"))?
                    .to_owned();
                let dest = if oid[2] == 3 { &mut cn } else { &mut profile };
                if dest.replace(text).is_some() {
                    return Err(Error::bad("Duplicate identity attribute"));
                }
            }
        }
    }
    Ok((
        cn.ok_or_else(|| Error::bad("Certificate CN required"))?,
        profile.ok_or_else(|| Error::bad("Certificate profile required"))?,
    ))
}
pub fn peer(cert: &[u8], suffix: &str) -> Result<Principal> {
    let (cn, profile) = subject(cert)?;
    let name = cn
        .strip_suffix(&format!(".{suffix}"))
        .ok_or_else(Error::denied)?;
    if !valid_name(name) || !matches!(profile.as_str(), "sy" | "op") {
        return Err(Error::denied());
    }
    Ok(Principal {
        name: name.into(),
        sysop: false,
        profile,
    })
}
pub fn encode(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}
pub struct Remote {
    config: Config,
    tls: Tls,
    session: Mutex<(String, String)>,
}
impl Remote {
    pub fn tls_config(&self, expected: &str) -> Result<rustls::ClientConfig> {
        self.tls.client_config(expected)
    }
    pub fn new(config: Config, tls: Tls) -> Self {
        Self {
            config,
            tls,
            session: Mutex::new((String::new(), String::new())),
        }
    }
    pub async fn request(
        &self,
        provider: &str,
        origin: &str,
        method: &str,
        path: &str,
        token: &str,
        body: &Value,
    ) -> Result<Value> {
        let u = url::Url::parse(origin)
            .map_err(|_| Error::unavailable("Authority is not configured"))?;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.path() != "/"
            || u.query().is_some()
            || u.fragment().is_some()
            || !path.starts_with('/')
            || path.starts_with("//")
            || path.contains(['\r', '\n', '#'])
        {
            return Err(Error::bad("Invalid authority origin/path"));
        }
        let client = self
            .tls
            .client(&format!("{}.{}", provider, self.config.cloud_suffix))?;
        let mut request = client.request(
            method
                .parse()
                .map_err(|_| Error::bad("Invalid upstream method"))?,
            format!("{}{path}", origin.trim_end_matches('/')),
        );
        if !body.is_null() {
            request = request.json(body)
        }
        if !token.is_empty() {
            request = request.header("Authorization", format!("Bearer IDENTITY-TOKEN//{token}"))
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| Error::unavailable("Pinned HTTPS authority unavailable"))?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::new(
                status,
                format!("Upstream {provider} rejected request"),
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::unavailable("Invalid authority response"))?
        {
            if bytes.len() + chunk.len() > 8 * 1024 * 1024 {
                return Err(Error::new(502, "Authority response exceeds limit"));
            }
            bytes.extend_from_slice(&chunk)
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::new(502, "Invalid authority JSON"))
    }
    async fn own_token(&self) -> Result<String> {
        let mut session = self.session.lock().await;
        if !session.0.is_empty() && !expired(&session.1) {
            return Ok(session.0.clone());
        }
        let password = String::from_utf8(secret(&self.config.password_file)?)
            .map_err(|_| Error::bad("Password is not UTF-8"))?;
        let out=self.request("Authentication",&self.config.authentication_url,"POST","/authentication/identity/login","",&json!({"systemName":self.config.name,"credentials":{"password":password.trim_end_matches(['\r','\n'])}})).await?;
        if s(&out, "token").is_empty() || expired(s(&out, "expirationTime")) {
            return Err(Error::new(502, "Invalid identity login response"));
        }
        *session = (s(&out, "token").into(), s(&out, "expirationTime").into());
        Ok(session.0.clone())
    }
    pub async fn call(
        &self,
        provider: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Value> {
        let origin = match provider {
            "Authentication" => &self.config.authentication_url,
            "ServiceRegistry" => &self.config.registry_url,
            "ConsumerAuthorization" => &self.config.authorization_url,
            _ => self
                .config
                .upstreams
                .get(provider)
                .ok_or_else(|| Error::unavailable("Explicit upstream is not configured"))?,
        };
        self.call_at(provider, origin, method, path, body).await
    }
    pub async fn call_certificate(
        &self,
        provider: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Value> {
        let origin = match provider {
            "ServiceRegistry" => &self.config.registry_url,
            _ => {
                return Err(Error::unavailable(
                    "Certificate bootstrap is not configured",
                ));
            }
        };
        self.request(provider, origin, method, path, "", body).await
    }
    pub async fn call_at(
        &self,
        provider: &str,
        origin: &str,
        method: &str,
        path: &str,
        body: &Value,
    ) -> Result<Value> {
        for _ in 0..2 {
            let token = self.own_token().await?;
            let result = self
                .request(provider, origin, method, path, &token, body)
                .await;
            if result.as_ref().is_err_and(|e| e.code == 401) {
                let mut session = self.session.lock().await;
                if session.0 == token {
                    session.0.clear()
                }
            } else {
                return result;
            }
        }
        Err(Error::new(502, "Authority rejected refreshed token"))
    }
}
// Refuses (403) a requester that Blacklist lists (security findings J12/J17, the counterpart of the Java BlacklistFilter
// and the Go core's checkBlacklist). Off without upstreams.Blacklist. Sysop, this system, Blacklist itself and
// blacklistExclude are not checked; an unreachable Blacklist refuses the request unless blacklistOptional is set.
pub async fn check_blacklist(app: &App, caller: &Principal) -> Result<()> {
    let config = &app.config;
    if !config.upstreams.contains_key("Blacklist")
        || caller.sysop
        || caller.name == config.name
        || caller.name == "Blacklist"
        || config.blacklist_exclude.contains(&caller.name)
    {
        return Ok(());
    }
    match app
        .remote
        .call(
            "Blacklist",
            "GET",
            &format!("/blacklist/check/{}", encode(&caller.name)),
            &Value::Null,
        )
        .await
    {
        Ok(Value::Bool(false)) => Ok(()),
        Ok(Value::Bool(true)) => Err(Error::new(
            403,
            format!("{} system is blacklisted", caller.name),
        )),
        _ if config.blacklist_optional => Ok(()),
        _ => Err(Error::new(
            403,
            "Blacklist system is not available, the system might be blacklisted",
        )),
    }
}
pub async fn authenticate(
    app: &App,
    peer: Principal,
    authorization: Option<&str>,
) -> Result<Principal> {
    let token = authorization
        .and_then(|s| s.strip_prefix("Bearer IDENTITY-TOKEN//"))
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.contains(['/', '?', '#', '\r', '\n']))
        .ok_or_else(|| Error::new(401, "Identity token required"))?;
    let verified = if app.config.role == "authentication" {
        crate::authentication::verify(&app.store, token)
    } else {
        app.remote
            .call(
                "Authentication",
                "GET",
                &format!("/authentication/identity/verify/{}", encode(token)),
                &Value::Null,
            )
            .await?
    };
    if verified["verified"] != true || s(&verified, "systemName") != peer.name {
        return Err(Error::new(401, "Token/certificate identity mismatch"));
    }
    Ok(Principal {
        sysop: verified["sysop"].as_bool().unwrap_or(false),
        ..peer
    })
}
