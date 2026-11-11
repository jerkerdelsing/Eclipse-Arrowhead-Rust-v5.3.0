// SPDX-License-Identifier: EPL-2.0
//! Minimal candidate-scoped Docker gateway; never exposes the daemon API directly.
use crate::secure::SYSTEMS;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::Semaphore,
};
#[derive(Clone)]
struct Gateway {
    project: String,
    socket: String,
    token: String,
    capacity: Arc<Semaphore>,
}
fn reply(code: u16, v: Value) -> Response {
    (
        StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_GATEWAY),
        Json(v),
    )
        .into_response()
}
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (a, b)| d | (a ^ b)) == 0
}
fn allowed_role(role: &str) -> bool {
    SYSTEMS.iter().any(|(_, r)| *r == role) && role != "localcloudmanager"
}
async fn docker(g: &Gateway, method: &str, path: &str) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(6),async{
  let mut stream=UnixStream::connect(&g.socket).await.map_err(|_|"Docker socket unavailable")?;
  stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.map_err(|_|"Docker request failed")?;
  let mut response=Vec::new();stream.take(8*1024*1024+1).read_to_end(&mut response).await.map_err(|_|"Docker read failed")?;if response.len()>8*1024*1024{return Err("Docker response too large".into())}
  let split=response.windows(4).position(|w|w==b"\r\n\r\n").ok_or("Invalid Docker response")?;let head=String::from_utf8_lossy(&response[..split]);let code=head.lines().next().and_then(|l|l.split_whitespace().nth(1)).and_then(|s|s.parse::<u16>().ok()).ok_or("Invalid Docker status")?;
  if !(200..300).contains(&code)&&!(method=="POST"&&code==304){return Err(format!("Docker rejected operation ({code})"))}
  let body=&response[split+4..];if head.to_ascii_lowercase().contains("transfer-encoding: chunked"){decode_chunked(body)}else{Ok(body.to_vec())}
 }).await.map_err(|_|"Docker deadline exceeded".to_owned())?
}
fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = vec![];
    loop {
        let line = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("Invalid chunk line")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&body[..line])
                .map_err(|_| "Invalid chunk")?
                .split(';')
                .next()
                .unwrap(),
            16,
        )
        .map_err(|_| "Invalid chunk size")?;
        body = &body[line + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > body.len().saturating_sub(2) || &body[size..size + 2] != b"\r\n" {
            return Err("Truncated chunk".into());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}
async fn list(g: &Gateway) -> Result<Vec<Value>, String> {
    let filter = security_encode(
        &json!({"label":[format!("com.docker.compose.project={}",g.project)]}).to_string(),
    );
    let bytes = docker(
        g,
        "GET",
        &format!("/containers/json?all=1&filters={filter}"),
    )
    .await?;
    let list: Vec<Value> =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid Docker inventory")?;
    Ok(list
        .into_iter()
        .filter(|c| c["Labels"]["com.docker.compose.project"] == g.project)
        .collect())
}
fn security_encode(s: &str) -> String {
    arrowhead_support_rust::security::encode(s)
}
fn demux(bytes: &[u8]) -> String {
    let mut result = vec![];
    let mut p = 0;
    while p + 8 <= bytes.len() && [1, 2].contains(&bytes[p]) && bytes[p + 1..p + 4] == [0, 0, 0] {
        let n = u32::from_be_bytes(bytes[p + 4..p + 8].try_into().unwrap()) as usize;
        p += 8;
        if n > bytes.len() - p {
            break;
        }
        result.extend_from_slice(&bytes[p..p + n]);
        p += n
    }
    if p == 0 {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        String::from_utf8_lossy(&result).into_owned()
    }
}
async fn handle(State(g): State<Gateway>, req: Request) -> Response {
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if !same(auth.as_bytes(), g.token.as_bytes()) {
        return reply(401, json!({"error":"Gateway authentication required"}));
    }
    let Ok(_permit) = g.capacity.clone().try_acquire_owned() else {
        return reply(429, json!({"error":"Gateway busy"}));
    };
    let path = req.uri().path().to_owned();
    let method = req.method().as_str().to_owned();
    let has_query = req.uri().query().is_some();
    drop(req);
    let result=async{
  if has_query{return Err((400,"Gateway queries are not accepted".into()))}
  let containers=list(&g).await.map_err(|e|(502,e))?;
  if method=="GET"&&path=="/containers"{return Ok(json!(containers.iter().map(inventory_row).collect::<Vec<_>>()))}
  let parts=path.trim_start_matches('/').split('/').collect::<Vec<_>>();let role=if parts.len()>=2{parts[1]}else{return Err((404,"Unknown gateway route".into()))};if !allowed_role(role){return Err((403,"Lifecycle/log target not permitted".into()))}
  let c=containers.iter().find(|c|c["Labels"]["com.docker.compose.service"]==role).ok_or((404,"No candidate service container".into()))?;let id=c["Id"].as_str().filter(|s|s.len()==64&&s.bytes().all(|b|b.is_ascii_hexdigit())).ok_or((502,"Invalid container id".into()))?;
  if parts.len()==2&&parts[0]=="logs"&&method=="GET"{let bytes=docker(&g,"GET",&format!("/containers/{id}/logs?stdout=1&stderr=1&timestamps=1&tail=180")).await.map_err(|e|(502,e))?;return Ok(json!({"service":role,"lines":demux(&bytes).lines().map(str::to_owned).collect::<Vec<_>>(),"collectedAt":chrono::Utc::now().to_rfc3339()}))}
  if parts.len()!=3||parts[0]!="containers"||method!="POST"||!["start","stop","restart"].contains(&parts[2]){return Err((403,"Daemon operation not permitted".into()))}
  let action=parts[2];let suffix=if action=="start"{String::new()}else{"?t=10".into()};docker(&g,"POST",&format!("/containers/{id}/{action}{suffix}")).await.map_err(|e|(502,e))?;Ok(json!({"service":role,"action":action,"accepted":true}))
 }.await;
    match result {
        Ok(v) => reply(200, v),
        Err((code, error)) => reply(code, json!({"error":error})),
    }
}
fn inventory_row(c: &Value) -> Value {
    let role = c["Labels"]["com.docker.compose.service"]
        .as_str()
        .unwrap_or("");
    let status = c["Status"].as_str().unwrap_or("");
    let health = ["healthy", "unhealthy", "starting"]
        .into_iter()
        .find(|h| status.contains(&format!("({h})")));
    json!({"id":c["Id"],"name":c["Names"].as_array().and_then(|n|n.first()).and_then(Value::as_str).unwrap_or("").trim_start_matches('/'),"service":role,"displayName":SYSTEMS.iter().find(|(_,r)|*r==role).map(|(n,_)|*n).unwrap_or(role),"image":c["Image"],"state":c["State"],"status":status,"health":health,"created":c["Created"],"managed":allowed_role(role)})
}
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let project = std::env::var("CANDIDATE_PROJECT")?;
    if project != "arrowhead-v53-test-cloud-rust" {
        return Err("Gateway restricted to the isolated candidate project".into());
    }
    let token = String::from_utf8(arrowhead_support_rust::config::secret(&std::env::var(
        "GATEWAY_TOKEN_FILE",
    )?)?)?
    .trim()
    .to_owned();
    if token.len() < 32 {
        return Err("Short gateway secret".into());
    }
    let g = Gateway {
        project,
        socket: std::env::var("DOCKER_SOCKET").unwrap_or_else(|_| "/var/run/docker.sock".into()),
        token,
        capacity: Arc::new(Semaphore::new(8)),
    };
    let app = Router::new()
        .fallback(handle)
        .layer(DefaultBodyLimit::max(0))
        .with_state(g);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        })
        .await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_allowlist_excludes_infrastructure_and_other_clouds() {
        for r in [
            "edge",
            "manager-docker-proxy",
            "localcloudmanager",
            "arrowhead-v52-test-cloud-serviceregistry-1",
            "../auth",
        ] {
            assert!(!allowed_role(r))
        }
        assert!(allowed_role("serviceregistry"));
    }
    #[test]
    fn chunk_parser_is_bounded_by_input() {
        assert_eq!(decode_chunked(b"3\r\nabc\r\n0\r\n\r\n").unwrap(), b"abc");
        assert!(decode_chunked(b"ffffffff\r\nx").is_err());
    }
    #[test]
    fn gateway_tokens_compare_exactly() {
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"ab"));
    }
}
