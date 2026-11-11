// SPDX-License-Identifier: EPL-2.0
use crate::*;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0; N];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| Error::new(500, "Secure randomness unavailable"))?;
    Ok(b)
}
fn master(app: &App) -> Result<Vec<u8>> {
    let key = config::secret(&app.config.token_secret_file)?;
    if key.len() < 32 {
        return Err(Error::bad("Token secret must contain at least 32 bytes"));
    }
    Ok(key)
}
pub fn reference(app: &App, raw: &str) -> Result<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&master(app)?)
        .map_err(|_| Error::bad("Token secret"))?;
    mac.update(raw.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}
fn sealing_key(app: &App) -> Result<aead::LessSafeKey> {
    aead::UnboundKey::new(&aead::AES_256_GCM, &Sha256::digest(master(app)?))
        .map(aead::LessSafeKey::new)
        .map_err(|_| Error::new(500, "Key wrapping configuration"))
}
fn seal(app: &App, provider: &str, key: &str) -> Result<String> {
    let nonce = random::<12>()?;
    let mut data = key.as_bytes().to_vec();
    sealing_key(app)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(provider.as_bytes()),
            &mut data,
        )
        .map_err(|_| Error::new(500, "Key wrapping failed"))?;
    Ok(STANDARD.encode([nonce.as_slice(), &data].concat()))
}
fn open(app: &App, provider: &str, sealed: &str) -> Result<Vec<u8>> {
    let data = STANDARD
        .decode(sealed)
        .map_err(|_| Error::bad("Invalid wrapped key"))?;
    if data.len() < 28 {
        return Err(Error::bad("Invalid wrapped key"));
    }
    let mut body = data[12..].to_vec();
    sealing_key(app)?
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(&data[..12])
                .map_err(|_| Error::bad("Invalid key nonce"))?,
            aead::Aad::from(provider.as_bytes()),
            &mut body,
        )
        .map(|b| b.to_vec())
        .map_err(|_| Error::new(500, "Wrapped key authentication failed"))
}
pub fn encrypt_wire(raw: &str, key: &[u8], algorithm: &str, iv: &str) -> Result<String> {
    let encrypted = if algorithm == "AES/CBC/PKCS5Padding" {
        let iv = STANDARD
            .decode(iv)
            .map_err(|_| Error::bad("Invalid AES IV"))?;
        macro_rules! cbc {
            ($cipher:ty) => {
                cbc::Encryptor::<$cipher>::new_from_slices(key, &iv)
                    .map_err(|_| Error::bad("Invalid AES key/IV"))?
                    .encrypt_padded_vec_mut::<Pkcs7>(raw.as_bytes())
            };
        }
        match key.len() {
            16 => cbc!(aes::Aes128),
            24 => cbc!(aes::Aes192),
            32 => cbc!(aes::Aes256),
            _ => return Err(Error::bad("Invalid AES key length")),
        }
    } else if algorithm == "AES/ECB/PKCS5Padding" {
        let mut data = raw.as_bytes().to_vec();
        let padding = 16 - data.len() % 16;
        data.resize(data.len() + padding, padding as u8);
        macro_rules! ecb {
            ($cipher:ty) => {{
                let cipher =
                    <$cipher>::new_from_slice(key).map_err(|_| Error::bad("Invalid AES key"))?;
                for chunk in data.chunks_exact_mut(16) {
                    let mut block = cipher::Block::<$cipher>::default();
                    block.copy_from_slice(chunk);
                    cipher.encrypt_block(&mut block);
                    chunk.copy_from_slice(&block);
                }
            }};
        }
        match key.len() {
            16 => ecb!(aes::Aes128),
            24 => ecb!(aes::Aes192),
            32 => ecb!(aes::Aes256),
            _ => return Err(Error::bad("Invalid AES key length")),
        };
        data
    } else {
        return Err(Error::bad("Unsupported AES algorithm"));
    };
    Ok(STANDARD.encode(encrypted))
}
fn signing_key(app: &App) -> Result<signature::RsaKeyPair> {
    let path = if app.config.signing_key.is_empty() {
        &app.config.private_key
    } else {
        &app.config.signing_key
    };
    let key = PrivateKeyDer::from_pem_slice(&config::secret(path)?)
        .map_err(|_| Error::bad("Invalid RSA key PEM"))?;
    match key {
        PrivateKeyDer::Pkcs8(k) => signature::RsaKeyPair::from_pkcs8(k.secret_pkcs8_der()),
        PrivateKeyDer::Pkcs1(k) => signature::RsaKeyPair::from_der(k.secret_pkcs1_der()),
        _ => return Err(Error::bad("RSA key required")),
    }
    .map_err(|_| Error::bad("Valid RSA signing key required"))
}
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8)
    } else {
        let bytes = content.len().to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 + (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(content);
    out
}
pub fn public_key(app: &App) -> Result<String> {
    let key = signing_key(app)?;
    let mut content = vec![
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let bits = [&[0][..], key.public_key().as_ref()].concat();
    content.extend(der(0x03, &bits));
    Ok(STANDARD.encode(der(0x30, &content)))
}
pub fn generate(app: &App, db: &mut Database, request: &Value, requester: &str) -> Result<Value> {
    let mut req = request.clone();
    if !req.is_object() {
        return Err(Error::bad("Token request must be an object"));
    }
    if s(&req, "consumerCloud").is_empty() {
        req["consumerCloud"] = "LOCAL".into()
    }
    if s(&req, "consumer").is_empty() {
        req["consumer"] = requester.into()
    }
    req["cloud"] = req["consumerCloud"].clone();
    authorization::validate_target(&mut req)?;
    required(&req, &["tokenVariant"])?;
    let variant = s(&req, "tokenVariant");
    let expiration = if s(&req, "expiresAt").is_empty() {
        expiry(app.config.token_ttl)
    } else {
        if expired(s(&req, "expiresAt")) {
            return Err(Error::bad("Token expiresAt must be in the future"));
        }
        s(&req, "expiresAt").into()
    };
    let mut limit = Value::Null;
    let mut expiry_value: Value = expiration.clone().into();
    let typ;
    let mut raw = match variant {
        "USAGE_LIMITED_TOKEN_AUTH" | "TIME_LIMITED_TOKEN_AUTH" => {
            typ = if variant.starts_with("USAGE") {
                "USAGE_LIMITED_TOKEN"
            } else {
                "TIME_LIMITED_TOKEN"
            };
            if typ == "USAGE_LIMITED_TOKEN" {
                let n = req["usageLimit"].as_u64().unwrap_or(1);
                if n == 0 || n > 1_000_000 {
                    return Err(Error::bad("Invalid usageLimit"));
                }
                limit = n.into();
                expiry_value = Value::Null;
            }
            URL_SAFE.encode(random::<32>()?)
        }
        "BASE64_SELF_CONTAINED_TOKEN_AUTH" => {
            typ = "SELF_CONTAINED_TOKEN";
            let fields = [
                s(&req, "consumerCloud"),
                s(&req, "consumer"),
                s(&req, "provider"),
                s(&req, "target"),
                s(&req, "scope"),
                s(&req, "targetType"),
                &expiration,
            ];
            URL_SAFE.encode(fields.join("|").as_bytes())
        }
        "RSA_SHA256_JSON_WEB_TOKEN_AUTH" | "RSA_SHA512_JSON_WEB_TOKEN_AUTH" => {
            typ = "SELF_CONTAINED_TOKEN";
            let algorithm = if variant.contains("SHA512") {
                "RS512"
            } else {
                "RS256"
            };
            let header =
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg":algorithm,"typ":"JWT"}))?);
            let until = chrono::DateTime::parse_from_rfc3339(&expiration)
                .map_err(|_| Error::bad("Invalid expiresAt"))?
                .timestamp();
            let mut claims = json!({"jti":uuid::Uuid::new_v4().to_string(),"iss":app.config.name,"iat":chrono::Utc::now().timestamp(),"nbf":chrono::Utc::now().timestamp()-60,"exp":until,"psn":req["provider"],"csn":req["consumer"],"ccn":req["consumerCloud"],"tat":req["targetType"],"tan":req["target"]});
            if !s(&req, "scope").is_empty() {
                claims["sco"] = req["scope"].clone()
            }
            let content = format!(
                "{header}.{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
            );
            let key = signing_key(app)?;
            let mut sig = vec![0; key.public().modulus_len()];
            key.sign(
                if algorithm == "RS512" {
                    &signature::RSA_PKCS1_SHA512
                } else {
                    &signature::RSA_PKCS1_SHA256
                },
                &SystemRandom::new(),
                content.as_bytes(),
                &mut sig,
            )
            .map_err(|_| Error::new(500, "Token signing failed"))?;
            format!("{content}.{}", URL_SAFE_NO_PAD.encode(sig))
        }
        _ => return Err(Error::bad("Unsupported tokenVariant")),
    };
    let token_reference = reference(app, &raw)?;
    let row = json!({"tokenType":typ,"variant":variant,"tokenReference":token_reference,"requester":requester,"consumerCloud":req["consumerCloud"],"consumer":req["consumer"],"provider":req["provider"],"targetType":req["targetType"],"target":req["target"],"scope":req["scope"],"createdAt":now(),"usageLimit":limit,"usageLeft":limit,"expiresAt":expiry_value,"token":null});
    if typ == "SELF_CONTAINED_TOKEN"
        && let Some(key) = table(db, "encryptionKeys").get(s(&req, "provider"))
    {
        let plain = open(app, s(&req, "provider"), s(key, "sealedKey"))?;
        raw = encrypt_wire(&raw, &plain, s(key, "algorithm"), s(key, "keyAdditive"))?;
    }
    table(db, "tokens").insert(token_reference, row.clone());
    let mut out = row;
    out["token"] = raw.into();
    Ok(out)
}
fn register_key(app: &App, db: &mut Database, provider: &str, req: &Value) -> Result<Value> {
    if !valid_name(provider) {
        return Err(Error::bad("Invalid provider name"));
    }
    let key = s(req, "key");
    if ![16, 24, 32].contains(&key.len()) {
        return Err(Error::bad("AES key must contain 16, 24 or 32 UTF-8 bytes"));
    }
    let algorithm = if s(req, "algorithm").is_empty() {
        "AES/ECB/PKCS5Padding"
    } else {
        s(req, "algorithm")
    };
    if !["AES/ECB/PKCS5Padding", "AES/CBC/PKCS5Padding"].contains(&algorithm) {
        return Err(Error::bad("Invalid AES algorithm"));
    }
    let iv = if algorithm.contains("CBC") {
        STANDARD.encode(random::<16>()?)
    } else {
        String::new()
    };
    let created = now();
    table(db,"encryptionKeys").insert(provider.into(),json!({"systemName":provider,"algorithm":algorithm,"keyAdditive":iv,"sealedKey":seal(app,provider,key)?,"createdAt":created}));
    Ok(
        json!({"systemName":provider,"rawKey":key,"algorithm":algorithm,"keyAdditive":iv,"createdAt":created}),
    )
}
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    params: &BTreeMap<String, String>,
    query: &Value,
    request: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    let management = path.contains("/mgmt/");
    if path.ends_with("/public-key") {
        return Ok((200, public_key(app)?.into()));
    }
    if path.contains("/token/verify/") {
        let token_reference = reference(app, &params["token"])?;
        return app.store.update(|db|{let Some(row)=table(db,"tokens").get_mut(&token_reference)else{return Ok((200,json!({"verified":false,"consumerCloud":null,"consumer":null,"targetType":null,"target":null,"scope":null})))};if s(row,"provider")!=caller.name{return Ok((200,json!({"verified":false})))}
if s(row,"tokenType")=="SELF_CONTAINED_TOKEN"{return Err(Error::bad("Self-contained tokens are verified by providers"))}let valid=if s(row,"tokenType")=="TIME_LIMITED_TOKEN"{!expired(s(row,"expiresAt"))}else{let left=row["usageLeft"].as_u64().unwrap_or(0);if left>0{row["usageLeft"]=(left-1).into();true}else{false}};Ok((200,if valid{json!({"verified":true,"consumerCloud":row["consumerCloud"],"consumer":row["consumer"],"targetType":row["targetType"],"target":row["target"],"scope":row["scope"]})}else{json!({"verified":false,"consumerCloud":null,"consumer":null,"targetType":null,"target":null,"scope":null})}))});
    }
    if path.ends_with("/encryption-key") {
        if method == "DELETE" {
            let names = if management {
                array(query, "systemNames")
            } else {
                vec![caller.name.clone().into()]
            };
            if names.is_empty() {
                return Err(Error::bad("systemNames required"));
            }
            return app.store.update(|db| {
                let mut found = false;
                for name in names {
                    let name = name.as_str().ok_or_else(|| Error::bad("Invalid name"))?;
                    found |= table(db, "encryptionKeys").remove(name).is_some();
                }
                Ok((
                    200,
                    if management {
                        Value::Null
                    } else {
                        found.into()
                    },
                ))
            });
        }
        let requests = if management {
            array(request, "list")
        } else {
            vec![request.clone()]
        };
        if requests.is_empty() || requests.len() > 100 {
            return Err(Error::bad("Nonempty bounded key list required"));
        }
        return app.store.update(|db| {
            let mut rows = Vec::new();
            for req in requests {
                rows.push(register_key(
                    app,
                    db,
                    if management {
                        s(&req, "systemName")
                    } else {
                        &caller.name
                    },
                    &req,
                )?)
            }
            Ok((
                200,
                if management {
                    json!({"count":rows.len(),"entries":rows})
                } else {
                    rows[0]["keyAdditive"].clone()
                },
            ))
        });
    }
    if path.ends_with("/generate") {
        if query["unbound"] == json!(["true"]) {
            return Err(Error::denied());
        }
        let mut requests = if management {
            array(request, "list")
        } else {
            vec![request.clone()]
        };
        if requests.is_empty() || requests.len() > 100 {
            return Err(Error::bad("list must contain 1..100 requests"));
        }
        for req in &mut requests {
            if !req.is_object() {
                return Err(Error::bad("Token request must be an object"));
            }
            if !management {
                req["consumer"] = caller.name.clone().into();
                req["consumerCloud"] = "LOCAL".into()
            }
            if s(req, "consumerCloud").is_empty() {
                req["consumerCloud"] = "LOCAL".into();
            }
            if !authorization::valid_cloud(s(req, "consumerCloud")) {
                return Err(Error::bad("Invalid consumerCloud"));
            }
            req["cloud"] = req["consumerCloud"].clone();
            if !authorization::granted(app, req.clone()).await? {
                return Err(Error::denied());
            }
        }
        return app.store.update(|db|{let mut rows=Vec::new();for req in requests{rows.push(generate(app,db,&req,&caller.name)?)}Ok((200,if management{json!({"count":rows.len(),"entries":rows})}else{let r=&rows[0];json!({"tokenType":r["tokenType"],"targetType":r["targetType"],"token":r["token"],"usageLimit":r["usageLimit"],"expiresAt":r["expiresAt"]})}))});
    }
    if path.ends_with("/revoke") {
        let references = array(query, "tokenReferences");
        if references.is_empty() {
            return Err(Error::bad("tokenReferences required"));
        }
        return app.store.update(|db| {
            for value in references {
                table(db, "tokens").remove(
                    value
                        .as_str()
                        .ok_or_else(|| Error::bad("Invalid token reference"))?,
                );
            }
            Ok((200, Value::Null))
        });
    }
    let rows = app
        .store
        .rows("tokens")
        .into_iter()
        .filter(|row| {
            [
                "requester",
                "tokenType",
                "consumerCloud",
                "consumer",
                "provider",
                "targetType",
                "target",
            ]
            .iter()
            .all(|k| s(request, k).is_empty() || request[*k] == row[*k])
        })
        .collect();
    Ok((200, page(rows, request, "entries")?))
}
