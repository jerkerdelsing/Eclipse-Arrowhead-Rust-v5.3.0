// SPDX-License-Identifier: EPL-2.0
#![allow(dead_code)]
use arrowhead_support_rust::*;
use axum::{Extension, Router};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, OnceLock},
};

pub const SUFFIX: &str = "RustCloud.Company.arrowhead.eu";
pub struct Temp(pub PathBuf);
impl Temp {
    pub fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("arrowhead-core-rust-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    pub fn file(&self, name: &str, data: impl AsRef<[u8]>) -> String {
        let p = self.0.join(name);
        fs::write(&p, data).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        p.to_string_lossy().into()
    }
}
impl Default for Temp {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub fn openssl(args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("OpenSSL is required only for isolated test PKI generation");
    assert!(
        out.status.success(),
        "OpenSSL test fixture failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
pub struct Pki {
    pub temp: Temp,
    pub ca: String,
    pub key: String,
}
impl Pki {
    fn new() -> Self {
        let temp = Temp::new();
        let key = temp.0.join("root.key").to_string_lossy().to_string();
        let ca = temp.0.join("root.pem").to_string_lossy().to_string();
        let config=temp.file("root.cnf","[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\nCN=Rust isolated test root\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n");
        openssl(&[
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", &key, "-out", &ca, "-days",
            "2", "-config", &config,
        ]);
        Self { temp, ca, key }
    }
    pub fn leaf(&self, temp: &Temp, name: &str, profile: &str) -> (String, String) {
        let prefix = uuid::Uuid::new_v4().to_string();
        let key = temp
            .0
            .join(format!("{prefix}.key"))
            .to_string_lossy()
            .to_string();
        let csr = temp
            .0
            .join(format!("{prefix}.csr"))
            .to_string_lossy()
            .to_string();
        let cert = temp
            .0
            .join(format!("{prefix}.pem"))
            .to_string_lossy()
            .to_string();
        let subject = format!("/CN={name}.{SUFFIX}/dnQualifier={profile}");
        openssl(&[
            "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", &key, "-out", &csr, "-subj",
            &subject,
        ]);
        let ext=temp.file(&format!("{prefix}.ext"),"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n");
        let serial = format!("0x{}", uuid::Uuid::new_v4().simple());
        openssl(&[
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            &self.ca,
            "-CAkey",
            &self.key,
            "-set_serial",
            &serial,
            "-out",
            &cert,
            "-days",
            "1",
            "-extfile",
            &ext,
        ]);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        (cert, key)
    }
}
pub fn pki() -> Arc<Pki> {
    static PKI: OnceLock<Arc<Pki>> = OnceLock::new();
    PKI.get_or_init(|| Arc::new(Pki::new())).clone()
}
pub struct Fixture {
    pub temp: Temp,
    pub config: Config,
    pub tls: security::Tls,
    pub app: App,
}
impl Fixture {
    pub fn new(role: &str) -> Self {
        Self::named(role, config::ROLES.iter().find(|r| r.0 == role).unwrap().1)
    }
    pub fn named(role: &str, name: &str) -> Self {
        let temp = Temp::new();
        let (cert, key) = pki().leaf(&temp, name, "sy");
        let password = temp.file("password", "private-test-password");
        let mut config:Config=serde_json::from_value(json!({"role":role,"name":name,"cloudSuffix":SUFFIX,"listen":"127.0.0.1:0","certificate":cert,"privateKey":key,"ca":pki().ca,"state":temp.0.join("state.json"),"passwordFile":password})).unwrap();
        config.validate().unwrap();
        let tls = security::Tls::load(&config).unwrap();
        let app = App::new(config.clone(), Store::memory(), tls.clone()).unwrap();
        Self {
            temp,
            config,
            tls,
            app,
        }
    }
    pub fn reconfigure(&mut self) {
        self.config.validate().unwrap();
        self.app = App::new(self.config.clone(), Store::memory(), self.tls.clone()).unwrap();
    }
}
pub fn caller(name: &str) -> Principal {
    Principal {
        name: name.into(),
        sysop: name == "Sysop",
        profile: "sy".into(),
    }
}
pub fn empty() -> Value {
    json!({})
}
pub struct Server {
    pub origin: String,
    pub app: App,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort()
    }
}
pub async fn start(app: App, tls: security::Tls) -> Server {
    start_router(app.clone(), tls, web::router(app)).await
}
pub async fn start_router(app: App, tls: security::Tls, router: Router) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    start_bound(app, tls, router, listener).await
}
pub async fn start_bound(
    app: App,
    tls: security::Tls,
    router: Router,
    listener: tokio::net::TcpListener,
) -> Server {
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let suffix = app.config.cloud_suffix.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let Ok(server) = tls.server_current() else {
                continue;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(server);
            let router = router.clone();
            let suffix = suffix.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Some(cert) = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                else {
                    return;
                };
                let Ok(peer) = security::peer(cert.as_ref(), &suffix) else {
                    return;
                };
                let router = router.layer(Extension(peer));
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        TokioIo::new(stream),
                        TowerToHyperService::new(router),
                    )
                    .await;
            });
        }
    });
    Server { origin, app, task }
}
pub async fn mock_auth() -> (Fixture, Server) {
    let f = Fixture::named("blacklist", "Authentication");
    let router=Router::new().fallback(|request:axum::extract::Request|async move{
        let path=request.uri().path().to_owned();
        if path.ends_with("/login") {
            let bytes=axum::body::to_bytes(request.into_body(),1<<20).await.unwrap();
            let req:Value=serde_json::from_slice(&bytes).unwrap();
            axum::Json(json!({"token":format!("token-{}",s(&req,"systemName")),"expirationTime":expiry(3600)}))
        }else{
            let token=percent_encoding::percent_decode_str(path.rsplit('/').next().unwrap()).decode_utf8_lossy();
            let name=token.strip_prefix("token-").unwrap_or("");
            axum::Json(json!({"verified":!name.is_empty(),"systemName":name,"sysop":name=="Sysop"}))
        }
    });
    let server = start_router(f.app.clone(), f.tls.clone(), router).await;
    (f, server)
}
pub async fn api(
    tls: &security::Tls,
    provider: &str,
    origin: &str,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (u16, Value) {
    let client = tls.client(&format!("{provider}.{SUFFIX}")).unwrap();
    let mut request = client.request(method.parse().unwrap(), format!("{origin}{path}"));
    if !token.is_empty() {
        request = request.header("authorization", format!("Bearer IDENTITY-TOKEN//{token}"))
    }
    if !body.is_null() {
        request = request.json(&body)
    }
    let response = request.send().await.unwrap();
    let code = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    let out = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).to_string().into());
    (code, out)
}
pub fn read(path: impl AsRef<Path>) -> Vec<u8> {
    fs::read(path).unwrap()
}
