// SPDX-License-Identifier: EPL-2.0
//! Endpoint principles (2026-11-09): every system has
//! 1. a configured listening port, where it accepts connections, and
//! 2. a predefined default, so that a first deployment works without extra configuration.
//!
//! Effective listening address, highest precedence first:
//!
//! | Source | Form |
//! |---|---|
//! | command line | `--server.port N` or `--server.port=N` (port only, host kept) |
//! | environment | `SERVER_PORT=N` (port only, host kept) |
//! | configuration file | `"listen": "host:port"` |
//! | built-in default | `127.0.0.1:<DEFAULT_PORTS>` |
//!
//! The names match Spring Boot (`server.port`, `SERVER_PORT`, `--server.port`) used by the Java implementation and
//! the default ports are the Arrowhead 5 defaults of the Java packaging. `advertisePort` is not changed: it is the
//! port published to the ServiceRegistry and may differ (e.g. a Docker host port).
use crate::{Error, Result};

/// Environment variable that overrides the configured listening port.
pub const PORT_ENV: &str = "SERVER_PORT";
/// Command-line flag that overrides `SERVER_PORT` and the configured listening port.
pub const PORT_FLAG: &str = "--server.port";
/// Built-in listen host; deployments that need remote access configure `listen`.
pub const DEFAULT_LISTEN_HOST: &str = "127.0.0.1";
/// Built-in listening port of every role of this runtime.
pub const DEFAULT_PORTS: [(&str, u16); 5] = [
    ("serviceorchestration-dynamic", 8441),
    ("serviceorchestration-simple", 8442),
    ("serviceregistry", 8443),
    ("authentication", 8444),
    ("consumer-authorization", 8445),
];

/// Built-in listening port of a role.
pub fn default_port(role: &str) -> Option<u16> {
    DEFAULT_PORTS.iter().find(|r| r.0 == role).map(|r| r.1)
}
/// Built-in listen address of a role.
pub fn default_listen(role: &str) -> Option<String> {
    default_port(role).map(|p| format!("{DEFAULT_LISTEN_HOST}:{p}"))
}
/// Validates a TCP port number given as text.
pub fn parse_port(raw: &str) -> Result<u16> {
    match raw.trim().parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(Error::bad("Listening port must be an integer in 1..65535")),
    }
}
/// Splits `host:port` (IPv6 hosts in brackets) and validates the port; a configured port 0 (OS-assigned, used
/// by tests) is accepted, overrides must name a real port.
fn split(listen: &str) -> Result<(&str, u16)> {
    let (host, port) = listen
        .rsplit_once(':')
        .ok_or_else(|| Error::bad("Invalid listen address (host:port required)"))?;
    if host.is_empty() || host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(Error::bad("Invalid listen address (host:port required)"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::bad("Invalid listen address (port must be 0..65535)"))?;
    Ok((host, port))
}
/// Replaces the port of `listen`, keeping its host.
pub fn with_port(listen: &str, port: u16) -> Result<String> {
    if port == 0 {
        return Err(Error::bad("Listening port must be an integer in 1..65535"));
    }
    Ok(format!("{}:{port}", split(listen)?.0))
}
/// Applies the built-in default (empty `listen`) and the `SERVER_PORT` value (`env`).
pub fn resolve(role: &str, listen: &str, env: Option<&str>) -> Result<String> {
    let listen = if listen.is_empty() {
        default_listen(role).ok_or_else(|| Error::bad("No default listening port for role"))?
    } else {
        listen.to_string()
    };
    split(&listen)?;
    match env.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => with_port(&listen, parse_port(v)?),
        None => Ok(listen),
    }
}
/// `--server.port` value of the runner arguments (after the program name), if present.
pub fn port_argument(args: &[String]) -> std::result::Result<Option<u16>, String> {
    let mut port = None;
    let mut i = 0;
    while i < args.len() {
        let value = if args[i] == PORT_FLAG {
            i += 1;
            args.get(i)
                .ok_or_else(|| format!("{PORT_FLAG} needs a value"))?
                .as_str()
        } else if let Some(v) = args[i]
            .strip_prefix(PORT_FLAG)
            .and_then(|v| v.strip_prefix('='))
        {
            v
        } else {
            i += 1;
            continue;
        };
        port = Some(parse_port(value).map_err(|e| format!("{PORT_FLAG}: {}", e.message))?);
        i += 1;
    }
    Ok(port)
}
/// Runner arguments without the `--server.port` flag and its value.
pub fn without_port_argument(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == PORT_FLAG {
            i += 2;
            continue;
        }
        if !args[i].starts_with(&format!("{PORT_FLAG}=")) {
            out.push(args[i].clone());
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }
    #[test]
    fn every_role_has_a_unique_default() {
        let mut seen = std::collections::BTreeMap::new();
        for (role, port) in DEFAULT_PORTS {
            assert!(port > 0, "{role}");
            assert!(
                seen.insert(port, role).is_none(),
                "{role} shares port {port}"
            );
        }
    }
    #[test]
    fn precedence_default_config_env_flag() {
        let (role, port) = DEFAULT_PORTS[0];
        assert_eq!(
            resolve(role, "", None).unwrap(),
            format!("127.0.0.1:{port}")
        );
        assert_eq!(resolve(role, "0.0.0.0:9000", None).unwrap(), "0.0.0.0:9000");
        assert_eq!(
            resolve(role, "0.0.0.0:9000", Some("")).unwrap(),
            "0.0.0.0:9000"
        );
        assert_eq!(
            resolve(role, "0.0.0.0:9000", Some("9100")).unwrap(),
            "0.0.0.0:9100"
        );
        assert_eq!(
            resolve(role, "[::]:9000", Some("9100")).unwrap(),
            "[::]:9100"
        );
        assert_eq!(resolve(role, "", Some("9100")).unwrap(), "127.0.0.1:9100");
        assert_eq!(with_port("0.0.0.0:9100", 9200).unwrap(), "0.0.0.0:9200");
        assert_eq!(resolve(role, "127.0.0.1:0", None).unwrap(), "127.0.0.1:0");
        for bad in ["0", "65536", "abc", "-1"] {
            assert!(resolve(role, "", Some(bad)).is_err(), "{bad}");
        }
        for bad in ["no-port", ":9000", "::1:9000", "host:x", "host:65536"] {
            assert!(resolve(role, bad, None).is_err(), "{bad}");
        }
        assert!(resolve("unknown-role", "", None).is_err());
    }
    #[test]
    fn port_flag_is_parsed_and_removed() {
        let a = s(&["--config", "c.json", "--server.port", "9300"]);
        assert_eq!(port_argument(&a).unwrap(), Some(9300));
        assert_eq!(without_port_argument(&a), s(&["--config", "c.json"]));
        let b = s(&["--server.port=9301", "--config", "c.json"]);
        assert_eq!(port_argument(&b).unwrap(), Some(9301));
        assert_eq!(without_port_argument(&b), s(&["--config", "c.json"]));
        assert_eq!(port_argument(&s(&["--config", "c.json"])).unwrap(), None);
        assert!(port_argument(&s(&["--server.port"])).is_err());
        assert!(port_argument(&s(&["--server.port=0"])).is_err());
    }
    #[test]
    fn resolved_addresses_accept_connections() {
        let accept = |addr: &str| match std::net::TcpListener::bind(addr) {
            Ok(listener) => {
                std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                eprintln!(
                    "{addr} is in use on this host (another system is running); bind check skipped"
                )
            }
            Err(e) => panic!("{addr}: {e}"),
        };
        for (role, _) in DEFAULT_PORTS {
            accept(&resolve(role, "", None).unwrap());
        }
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);
        let (role, _) = DEFAULT_PORTS[0];
        let addr = resolve(role, "", Some(&port.to_string())).unwrap();
        assert_eq!(addr, format!("127.0.0.1:{port}"));
        accept(&addr);
    }
}
