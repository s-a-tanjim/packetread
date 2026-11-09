use crate::decode::{Protocol, Summary};
use std::net::IpAddr;

#[derive(Clone, Debug, Default)]
pub struct Filter {
    predicates: Vec<Predicate>,
}

#[derive(Clone, Debug)]
enum Predicate {
    Protocol(Protocol),
    Address(IpAddr),
    Source(IpAddr),
    Destination(IpAddr),
    Port(u16),
}

impl Filter {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > 1024 {
            return Err("Filter is limited to 1024 bytes".into());
        }
        let mut predicates = Vec::new();
        for token in input.split_whitespace() {
            let (key, value) = token
                .split_once('=')
                .ok_or("Use key=value, e.g. proto=tcp port=443")?;
            let key = key.to_ascii_lowercase();
            let predicate = match key.as_str() {
                "proto" => Predicate::Protocol(match value.to_ascii_lowercase().as_str() {
                    "tcp" => Protocol::Tcp,
                    "udp" => Protocol::Udp,
                    "dns" => Protocol::Dns,
                    "arp" => Protocol::Arp,
                    "icmp" => Protocol::Icmp,
                    "ipv4" => Protocol::Ipv4,
                    "ipv6" => Protocol::Ipv6,
                    "unknown" => Protocol::Unknown,
                    _ => return Err(format!("Unknown protocol: {value}")),
                }),
                "addr" | "src" | "dst" => {
                    let address = value
                        .parse::<IpAddr>()
                        .map_err(|_| format!("Invalid IP address: {value}"))?;
                    match key.as_str() {
                        "src" => Predicate::Source(address),
                        "dst" => Predicate::Destination(address),
                        _ => Predicate::Address(address),
                    }
                }
                "port" => {
                    Predicate::Port(value.parse::<u16>().map_err(|_| "Port must be 0–65535")?)
                }
                _ => {
                    return Err(format!(
                        "Unknown field: {key}. Use proto, addr, src, dst, port"
                    ))
                }
            };
            predicates.push(predicate);
        }
        Ok(Self { predicates })
    }

    pub fn matches(&self, packet: &Summary) -> bool {
        self.predicates.iter().all(|predicate| match predicate {
            Predicate::Protocol(Protocol::Ipv4) => {
                matches!(packet.src, Some(IpAddr::V4(_))) && packet.protocol != Protocol::Arp
            }
            Predicate::Protocol(Protocol::Ipv6) => matches!(packet.src, Some(IpAddr::V6(_))),
            Predicate::Protocol(Protocol::Udp) => {
                matches!(packet.protocol, Protocol::Udp | Protocol::Dns)
            }
            Predicate::Protocol(protocol) => packet.protocol == *protocol,
            Predicate::Address(address) => {
                packet.src == Some(*address) || packet.dst == Some(*address)
            }
            Predicate::Source(address) => packet.src == Some(*address),
            Predicate::Destination(address) => packet.dst == Some(*address),
            Predicate::Port(port) => {
                packet.src_port == Some(*port) || packet.dst_port == Some(*port)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn combines_predicates_and_rejects_invalid_input() {
        let packet = Summary {
            protocol: Protocol::Tcp,
            src: Some("192.0.2.1".parse().unwrap()),
            dst_port: Some(443),
            ..Summary::default()
        };
        assert!(Filter::parse("proto=tcp port=443 src=192.0.2.1")
            .unwrap()
            .matches(&packet));
        assert!(!Filter::parse("port=80").unwrap().matches(&packet));
        for bad in ["tcp", "port=65536", "addr=no", "proto=http", "foo=bar"] {
            assert!(Filter::parse(bad).is_err());
        }
    }
    #[test]
    fn dns_is_also_udp() {
        let packet = Summary {
            protocol: Protocol::Dns,
            ..Summary::default()
        };
        assert!(Filter::parse("proto=udp").unwrap().matches(&packet));
    }
}
