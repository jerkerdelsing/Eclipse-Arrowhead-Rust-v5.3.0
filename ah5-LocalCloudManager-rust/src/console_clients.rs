// SPDX-License-Identifier: EPL-2.0
//! Which clients may connect to the console listener (security finding SOS-1, 2026-11-09).
//!
//! The console's `Host`/`Origin` check stops a browser on another site, but any program sets those headers itself, so
//! it is no barrier for another system on a shared network. The console therefore filters the TCP connection by source
//! address before the TLS handshake and answers only:
//!
//! - the loopback address;
//! - the gateway of one of the container's directly connected IPv4 networks. Docker assigns the gateway as the first
//!   address of the subnet and forwards a published port from it; no container can hold that address;
//! - the addresses, CIDR ranges and DNS names of `consoleClients` (e.g. a TCP relay that publishes the console). A
//!   name is resolved through the deployment's resolver and re-read every 10 seconds; it fails closed when it does
//!   not resolve.
//!
//! This is the counterpart of the Java LocalCloudManager's `ConsoleClients` (J6).
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

const REFRESH: Duration = Duration::from_secs(10);
const ROUTES: &str = "/proc/net/route";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    address: IpAddr,
    prefix: u8,
}
impl Net {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                masked(u32::from(n).into(), self.prefix, 32)
                    == masked(u32::from(a).into(), self.prefix, 32)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                masked(u128::from(n), self.prefix, 128) == masked(u128::from(a), self.prefix, 128)
            }
            _ => false,
        }
    }
}
fn masked(value: u128, prefix: u8, bits: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        value >> (bits - prefix)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Net(Net),
    Name(String),
}

/// Resolved allow-list: when it was read, the network gateways and the configured networks.
type Resolved = (Instant, Vec<Ipv4Addr>, Vec<Net>);

pub struct ConsoleClients {
    entries: Vec<Entry>,
    routes: Option<String>,
    cache: Mutex<Option<Resolved>>,
}

impl ConsoleClients {
    /// `consoleClients` of CONFIG.json: IP addresses, CIDR ranges or DNS names.
    pub fn new(list: &[String]) -> Result<Self, String> {
        Ok(Self {
            entries: parse(list)?,
            routes: Some(ROUTES.into()),
            cache: Mutex::new(None),
        })
    }
    #[cfg(test)]
    fn with_routes(list: &[String], routes: Option<String>) -> Self {
        Self {
            entries: parse(list).unwrap(),
            routes,
            cache: Mutex::new(None),
        }
    }

    pub async fn allowed(&self, remote: IpAddr) -> bool {
        let remote = unmapped(remote);
        if remote.is_loopback() {
            return true;
        }
        let cached = self
            .cache
            .lock()
            .ok()
            .and_then(|c| c.clone())
            .filter(|(at, _, _)| at.elapsed() < REFRESH);
        let (gateways, nets) = match cached {
            Some((_, g, n)) => (g, n),
            None => {
                let (g, n) = self.refresh().await;
                if let Ok(mut c) = self.cache.lock() {
                    *c = Some((Instant::now(), g.clone(), n.clone()));
                }
                (g, n)
            }
        };
        allowed_with(remote, &gateways, &nets)
    }

    async fn refresh(&self) -> (Vec<Ipv4Addr>, Vec<Net>) {
        let gateways = match &self.routes {
            Some(path) => tokio::fs::read_to_string(path)
                .await
                .map(|t| gateways(&t))
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let mut nets = Vec::new();
        for entry in &self.entries {
            match entry {
                Entry::Net(n) => nets.push(*n),
                Entry::Name(name) => {
                    if let Ok(found) = tokio::net::lookup_host((name.as_str(), 0)).await {
                        for a in found {
                            let ip = unmapped(a.ip());
                            nets.push(Net {
                                address: ip,
                                prefix: if ip.is_ipv4() { 32 } else { 128 },
                            });
                        }
                    }
                }
            }
        }
        (gateways, nets)
    }
}

fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn allowed_with(remote: IpAddr, gateways: &[Ipv4Addr], nets: &[Net]) -> bool {
    let remote = unmapped(remote);
    remote.is_loopback()
        || matches!(remote, IpAddr::V4(v4) if gateways.contains(&v4))
        || nets.iter().any(|n| n.contains(remote))
}

fn parse(list: &[String]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for raw in list {
        let entry = raw.trim();
        let bad =
            || format!("consoleClients: {entry:?} is not an IP address, CIDR range or DNS name");
        if let Some((host, prefix)) = entry.split_once('/') {
            let address = host.parse::<IpAddr>().map_err(|_| bad())?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            let prefix = prefix
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(bad)?;
            out.push(Entry::Net(Net {
                address: unmapped(address),
                prefix,
            }));
        } else if let Ok(address) = entry.parse::<IpAddr>() {
            let address = unmapped(address);
            out.push(Entry::Net(Net {
                address,
                prefix: if address.is_ipv4() { 32 } else { 128 },
            }));
        } else if valid_name(entry) {
            out.push(Entry::Name(entry.to_ascii_lowercase()));
        } else {
            return Err(bad());
        }
    }
    Ok(out)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Gateways of the directly connected IPv4 networks in `/proc/net/route`: first address of each subnet shorter than /31.
fn gateways(routes: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for line in routes.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let hex = |s: &str| u32::from_str_radix(s, 16).ok();
        let (Some(dest), Some(gw), Some(flags), Some(mask)) =
            (hex(f[1]), hex(f[2]), hex(f[3]), hex(f[7]))
        else {
            continue;
        };
        // /proc/net/route prints addresses in host (little-endian) byte order
        let network = u32::from_be_bytes(dest.to_le_bytes());
        let prefix = u32::from_be_bytes(mask.to_le_bytes()).leading_ones();
        if gw != 0 || flags & 1 == 0 || dest == 0 || !(1..31).contains(&prefix) {
            continue;
        }
        let g = Ipv4Addr::from(network.wrapping_add(1));
        if !out.contains(&g) {
            out.push(g);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROUTE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00B0A8C0\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0\n\
eth1\t00000000\t01A0A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
eth1\t00A0A8C0\t00000000\t0001\t0\t0\t0\t00F0FFFF\t0\t0\t0\n";
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn gateways_are_first_subnet_addresses() {
        assert_eq!(
            gateways(ROUTE),
            vec![
                Ipv4Addr::new(192, 168, 176, 1),
                Ipv4Addr::new(192, 168, 160, 1)
            ]
        );
    }

    #[test]
    fn loopback_and_gateway_allowed_other_systems_refused() {
        let g = gateways(ROUTE);
        assert!(allowed_with(ip("127.0.0.1"), &g, &[]));
        assert!(allowed_with(ip("::1"), &g, &[]));
        assert!(allowed_with(ip("::ffff:127.0.0.1"), &g, &[]));
        assert!(allowed_with(ip("192.168.176.1"), &g, &[]));
        assert!(allowed_with(ip("::ffff:192.168.160.1"), &g, &[]));
        assert!(!allowed_with(ip("192.168.176.9"), &g, &[]));
        assert!(!allowed_with(ip("192.168.176.0"), &g, &[]));
        assert!(!allowed_with(ip("fe80::1"), &g, &[]));
    }

    #[test]
    fn configured_addresses_and_ranges() {
        let nets: Vec<Net> = parse(&list(&["10.1.2.3", "172.20.0.0/16", "fd00::/8"]))
            .unwrap()
            .into_iter()
            .filter_map(|e| if let Entry::Net(n) = e { Some(n) } else { None })
            .collect();
        assert!(allowed_with(ip("10.1.2.3"), &[], &nets));
        assert!(!allowed_with(ip("10.1.2.4"), &[], &nets));
        assert!(allowed_with(ip("172.20.255.1"), &[], &nets));
        assert!(!allowed_with(ip("172.21.0.1"), &[], &nets));
        assert!(allowed_with(ip("fd12::5"), &[], &nets));
        assert!(!allowed_with(ip("fe80::5"), &[], &nets));
    }

    #[test]
    fn invalid_entries_refused() {
        for bad in [
            "",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0/8",
            "-edge",
            "a b",
            "999.1.1.1",
            "edge/24",
            "http://edge",
        ] {
            assert!(parse(&list(&[bad])).is_err(), "{bad}");
        }
        assert_eq!(
            parse(&list(&["Edge"])).unwrap(),
            vec![Entry::Name("edge".into())]
        );
        assert!(parse(&list(&["0.0.0.0/0"])).is_ok());
    }

    #[tokio::test]
    async fn names_resolve_and_fail_closed() {
        let c = ConsoleClients::with_routes(&list(&["localhost", "no-such-host.invalid"]), None);
        assert!(c.allowed(ip("127.0.0.1")).await);
        assert!(!c.allowed(ip("192.0.2.10")).await);
        let none = ConsoleClients::with_routes(&[], None);
        assert!(
            !none.allowed(ip("192.168.176.1")).await,
            "no route table: only loopback"
        );
    }
}
