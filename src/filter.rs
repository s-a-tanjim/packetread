//! Display-filter language: predicates joined by AND (also implied by
//! whitespace), OR, NOT and parentheses. See `docs/USAGE.md` for the reference.
use crate::decode::{diag, Packet, Protocol};
use regex::bytes::{Regex, RegexBuilder};
use std::net::IpAddr;

#[derive(Clone, Debug, Default)]
pub struct Filter {
    root: Option<Node>,
}

#[derive(Clone, Debug)]
enum Node {
    Or(Box<Node>, Box<Node>),
    And(Box<Node>, Box<Node>),
    Not(Box<Node>),
    Test(Test),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Side {
    Either,
    Source,
    Destination,
}

#[derive(Clone, Copy, Debug)]
enum Number {
    Port(Side),
    Length,
    Ttl,
    Vlan,
    Stream,
    Id,
    Seq,
    Ack,
    Window,
    /// Capture time in whole seconds since the Unix epoch.
    Time,
}

#[derive(Clone, Copy, Debug)]
enum Text {
    Info,
    Comment,
    Warning,
    Bytes,
    Payload,
    /// Any layer or field label of the decoded protocol tree.
    Field,
}

#[derive(Clone, Debug)]
enum Matcher {
    /// Lowercased needle; matching ignores ASCII case.
    Contains(Vec<u8>),
    Regex(Regex),
}

#[derive(Clone, Debug)]
enum Test {
    Protocol(Protocol),
    /// Network address and prefix length.
    Address(Side, IpAddr, u8),
    /// Inclusive range.
    Number(Number, u64, u64),
    Flags(u8),
    Analysis(u8),
    Text(Text, Matcher),
    Marked,
    HasWarning,
    HasComment,
    Reassembled,
    /// A named field of the protocol tree, such as `http.host`.
    Named(Named, Compare),
}

/// `layer.key`: the layer's label starts with `layer` and the field's name
/// (the label before its colon) is `key`, both compared as slugs.
#[derive(Clone, Debug)]
struct Named {
    layer: String,
    key: String,
}

#[derive(Clone, Debug)]
enum Compare {
    Exists,
    /// Lowercased; equals the whole value or one of its words.
    Equal(String),
    /// Inclusive range for the value's leading number.
    Range(u64, u64),
    Text(Matcher),
}

/// Lowercase with every run of other characters turned into one underscore.
fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    out.trim_end_matches('_').to_string()
}

/// Wireshark spellings of common fields, mapped to this decoder's names.
const FIELD_ALIASES: [(&str, &str); 22] = [
    ("ip.src", "ipv4.source"),
    ("ip.dst", "ipv4.destination"),
    ("ip.ttl", "ipv4.ttl"),
    ("ip.len", "ipv4.total_length"),
    ("ipv6.src", "ipv6.source"),
    ("ipv6.dst", "ipv6.destination"),
    ("ipv6.hlim", "ipv6.hop_limit"),
    ("eth.src", "ethernet.source"),
    ("eth.dst", "ethernet.destination"),
    ("eth.type", "ethernet.ethertype"),
    ("tcp.srcport", "tcp.source_port"),
    ("tcp.dstport", "tcp.destination_port"),
    ("tcp.window_size", "tcp.window"),
    ("udp.srcport", "udp.source_port"),
    ("udp.dstport", "udp.destination_port"),
    ("udp.length", "udp.length"),
    ("dns.id", "dns.transaction_id"),
    ("dns.qry.name", "dns.question"),
    ("dns.resp.name", "dns.record"),
    ("tls.handshake.extensions_server_name", "tls.server_name"),
    ("dhcp.hostname", "dhcp.host_name"),
    ("wlan.ssid", "802_11.ssid"),
];

/// Layer names a named field may start with, besides the protocol names.
const LAYERS: [&str; 20] = [
    "ethernet",
    "802_1q",
    "linux",
    "loopback",
    "radiotap",
    "ieee_802_11",
    "802_11",
    "llc",
    "eapol",
    "pppoe",
    "gre",
    "vxlan",
    "spanning",
    "onc_rpc",
    "smb1",
    "smb2",
    "smb3",
    "icmpv4",
    "icmpv6",
    "authentication",
];

fn named(field: &str) -> Option<Named> {
    let field = FIELD_ALIASES
        .iter()
        .find(|(alias, _)| *alias == field)
        .map_or(field, |(_, name)| name);
    let (layer, key) = field.split_once('.')?;
    let known = LAYERS.contains(&layer)
        || Protocol::ALL
            .iter()
            .any(|protocol| protocol.name().eq_ignore_ascii_case(layer));
    (known && !key.is_empty()).then(|| Named {
        layer: layer.into(),
        key: slug(key),
    })
}

/// A named protocol field such as `http.host`, for custom columns.
#[derive(Clone, Debug)]
pub struct Field(Named);

impl Field {
    pub fn parse(name: &str) -> Result<Self, String> {
        named(&name.to_ascii_lowercase())
            .map(Self)
            .ok_or_else(|| format!("Unknown field: {name}"))
    }

    /// The field's first value in `packet`.
    pub fn value(&self, packet: &Packet) -> Option<String> {
        self.0.values(packet).into_iter().next()
    }
}

/// Filter words that start with `prefix`, for completion in the filter bar.
pub fn completions(prefix: &str) -> Vec<String> {
    const WORDS: [&str; 33] = [
        "proto=",
        "addr=",
        "src=",
        "dst=",
        "port=",
        "sport=",
        "dport=",
        "len",
        "ttl",
        "vlan",
        "stream=",
        "id=",
        "time",
        "tcp.flags=",
        "tcp.seq",
        "tcp.ack",
        "tcp.window",
        "tcp.analysis=",
        "info",
        "comment",
        "warning",
        "bytes",
        "payload",
        "field",
        "marked",
        "reassembled",
        "and",
        "or",
        "not",
        "contains",
        "matches",
        "http.host",
        "http.request.method",
    ];
    let prefix = prefix.to_ascii_lowercase();
    let flags = ["fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"];
    let mut out: Vec<String> = WORDS.iter().map(|word| word.to_string()).collect();
    out.extend(FIELD_ALIASES.iter().map(|(alias, _)| alias.to_string()));
    out.extend(
        Protocol::ALL
            .iter()
            .map(|protocol| format!("proto={}", protocol.name().to_ascii_lowercase())),
    );
    out.extend(
        diag::NAMES
            .iter()
            .map(|(_, name)| format!("tcp.analysis={name}")),
    );
    out.extend(flags.iter().map(|flag| format!("tcp.flags={flag}")));
    out.retain(|word| word.starts_with(&prefix) && *word != prefix);
    // Values are only offered once their field is typed.
    if !prefix.contains('=') {
        out.retain(|word| !word.contains('=') || word.ends_with('='));
    }
    out.sort();
    out.dedup();
    out
}

/// The leading number of a field value: decimal, or hexadecimal after `0x`.
fn leading_number(value: &str) -> Option<u64> {
    let token = value.split([' ', ',', ')', '(']).find(|t| !t.is_empty())?;
    match token.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => token.parse().ok(),
    }
}

impl Named {
    /// Values of the matching fields in `packet`'s protocol tree.
    fn values(&self, packet: &Packet) -> Vec<String> {
        let mut out = Vec::new();
        for layer in packet.layers() {
            // "HTTP/2" and "http2" are the same layer: underscores do not count.
            if !slug(&layer.label)
                .replace('_', "")
                .starts_with(&self.layer.replace('_', ""))
            {
                continue;
            }
            for (index, field) in layer.fields.iter().enumerate() {
                match field.label.split_once(": ") {
                    Some((key, value)) if slug(key) == self.key => out.push(value.to_string()),
                    // The HTTP start line has no name of its own.
                    None if index == 0 && self.layer == "http" => {
                        let mut words = field.label.split(' ');
                        let (first, second) = (words.next(), words.next());
                        let response = first.is_some_and(|word| word.starts_with("HTTP/"));
                        let value = match (self.key.as_str(), response) {
                            ("request_method", false) => first,
                            ("request_uri", false) | ("response_code", true) => second,
                            _ => None,
                        };
                        out.extend(value.map(str::to_string));
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

impl Compare {
    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Exists => true,
            Self::Equal(wanted) => {
                let value = value.to_ascii_lowercase();
                value == *wanted
                    || value.split([' ', ',', '(', ')']).any(|word| word == wanted)
                    || matches!(
                        (leading_number(&value), leading_number(wanted)),
                        (Some(a), Some(b)) if a == b
                    )
            }
            Self::Range(low, high) => {
                leading_number(value).is_some_and(|n| (*low..=*high).contains(&n))
            }
            Self::Text(matcher) => matcher.matches(value.as_bytes()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Open,
    Close,
    Not,
    And,
    Or,
    Op(&'static str),
    Word(String),
    Quoted(String),
}

const OPERATORS: [&str; 8] = ["==", "!=", "<=", ">=", "=", "<", ">", "~"];
const FIELDS: &str =
    "proto, addr, src, dst, port, sport, dport, len, ttl, vlan, stream, id, time, \
    tcp.flags, tcp.seq, tcp.ack, tcp.window, tcp.analysis, info, comment, warning, bytes, payload, \
    field, or a protocol field such as http.host";

fn tokens(input: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut rest = input.trim_start();
    while let Some(first) = rest.chars().next() {
        let (token, used) = if let Some(op) = OPERATORS.iter().find(|op| rest.starts_with(**op)) {
            (Token::Op(op), op.len())
        } else if rest.starts_with("&&") {
            (Token::And, 2)
        } else if rest.starts_with("||") {
            (Token::Or, 2)
        } else if first == '"' {
            let end = rest[1..].find('"').ok_or("Unterminated quote")?;
            (Token::Quoted(rest[1..=end].into()), end + 2)
        } else {
            match first {
                '(' => (Token::Open, 1),
                ')' => (Token::Close, 1),
                '!' => (Token::Not, 1),
                _ => {
                    let end = rest
                        .find(|c: char| c.is_whitespace() || "()=!<>~&|\"".contains(c))
                        .unwrap_or(rest.len());
                    if end == 0 {
                        return Err(format!("Unexpected character: {first}"));
                    }
                    let word = &rest[..end];
                    let token = match word.to_ascii_lowercase().as_str() {
                        "and" => Token::And,
                        "or" => Token::Or,
                        "not" => Token::Not,
                        "contains" => Token::Op("contains"),
                        "matches" => Token::Op("~"),
                        _ => Token::Word(word.into()),
                    };
                    (token, end)
                }
            }
        };
        out.push(token);
        rest = rest[used..].trim_start();
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }
    fn next(&mut self) -> Option<Token> {
        self.position += 1;
        self.tokens.get(self.position - 1).cloned()
    }
    fn or(&mut self, depth: usize) -> Result<Node, String> {
        let mut node = self.and(depth)?;
        while self.peek() == Some(&Token::Or) {
            self.position += 1;
            node = Node::Or(Box::new(node), Box::new(self.and(depth)?));
        }
        Ok(node)
    }
    fn and(&mut self, depth: usize) -> Result<Node, String> {
        let mut node = self.unary(depth)?;
        loop {
            match self.peek() {
                Some(Token::And) => self.position += 1,
                Some(Token::Or | Token::Close) | None => return Ok(node),
                _ => {}
            }
            node = Node::And(Box::new(node), Box::new(self.unary(depth)?));
        }
    }
    fn unary(&mut self, depth: usize) -> Result<Node, String> {
        if depth > 32 {
            return Err("Filter is nested too deeply".into());
        }
        match self.next() {
            Some(Token::Not) => Ok(Node::Not(Box::new(self.unary(depth + 1)?))),
            Some(Token::Open) => {
                let node = self.or(depth + 1)?;
                match self.next() {
                    Some(Token::Close) => Ok(node),
                    _ => Err("Missing closing parenthesis".into()),
                }
            }
            Some(Token::Word(field)) => self.test(&field.to_ascii_lowercase()),
            Some(Token::Close) => Err("Unexpected closing parenthesis".into()),
            _ => Err("Expected a predicate such as proto=tcp".into()),
        }
    }
    fn test(&mut self, field: &str) -> Result<Node, String> {
        let Some(Token::Op(op)) = self.peek().cloned() else {
            return Ok(Node::Test(match field {
                "marked" => Test::Marked,
                "warning" => Test::HasWarning,
                "comment" => Test::HasComment,
                "reassembled" => Test::Reassembled,
                _ => match named(field) {
                    Some(named) => Test::Named(named, Compare::Exists),
                    None => return Err("Use key=value, e.g. proto=tcp port=443".into()),
                },
            }));
        };
        self.position += 1;
        let (value, quoted) = match self.next() {
            Some(Token::Word(value)) => (value, false),
            Some(Token::Quoted(value)) => (value, true),
            _ => return Err(format!("Missing value after {field}{op}")),
        };
        let equality = matches!(op, "=" | "==" | "!=");
        let only_equality = |test: Test| {
            if equality {
                Ok(test)
            } else {
                Err(format!("{field} supports only = and !="))
            }
        };
        let test = match field {
            "proto" => only_equality(Test::Protocol(protocol(&value)?))?,
            "addr" | "src" | "dst" => {
                let (address, prefix) = network(&value)?;
                let side = match field {
                    "src" => Side::Source,
                    "dst" => Side::Destination,
                    _ => Side::Either,
                };
                only_equality(Test::Address(side, address, prefix))?
            }
            "tcp.flags" => only_equality(Test::Flags(flags(&value)?))?,
            "tcp.analysis" => only_equality(Test::Analysis(analysis(&value)?))?,
            "info" | "comment" | "warning" | "bytes" | "payload" | "field" => {
                let text = match field {
                    "info" => Text::Info,
                    "comment" => Text::Comment,
                    "warning" => Text::Warning,
                    "bytes" => Text::Bytes,
                    "field" => Text::Field,
                    _ => Text::Payload,
                };
                let raw = matches!(text, Text::Bytes | Text::Payload);
                let matcher = match op {
                    "~" => Matcher::Regex(
                        RegexBuilder::new(&value)
                            .case_insensitive(!raw)
                            .unicode(!raw)
                            .size_limit(1 << 20)
                            .build()
                            .map_err(|_| format!("Invalid regular expression: {value}"))?,
                    ),
                    "contains" | "=" | "==" if raw && !quoted => Matcher::Contains(hex(&value)?),
                    "contains" | "=" | "==" => Matcher::Contains(value.to_ascii_lowercase().into()),
                    _ => return Err(format!("{field} supports contains and ~")),
                };
                return Ok(Node::Test(Test::Text(text, matcher)));
            }
            _ if !matches!(field, "tcp.seq" | "tcp.ack" | "tcp.window")
                && named(field).is_some() =>
            {
                let number = |text: &str| {
                    leading_number(text).ok_or(format!("{field} {op} needs a number, not {text}"))
                };
                let compare = match op {
                    "=" | "==" | "!=" => Compare::Equal(value.to_ascii_lowercase()),
                    "<" => Compare::Range(
                        0,
                        number(&value)?.checked_sub(1).ok_or("Nothing is below 0")?,
                    ),
                    "<=" => Compare::Range(0, number(&value)?),
                    ">" => Compare::Range(
                        number(&value)?.checked_add(1).ok_or("Number too large")?,
                        u64::MAX,
                    ),
                    ">=" => Compare::Range(number(&value)?, u64::MAX),
                    "~" => Compare::Text(Matcher::Regex(
                        RegexBuilder::new(&value)
                            .case_insensitive(true)
                            .size_limit(1 << 20)
                            .build()
                            .map_err(|_| format!("Invalid regular expression: {value}"))?,
                    )),
                    _ => Compare::Text(Matcher::Contains(value.to_ascii_lowercase().into())),
                };
                match named(field) {
                    Some(named) => Test::Named(named, compare),
                    None => return Err(format!("Unknown field: {field}")),
                }
            }
            _ => {
                let number = match field {
                    "port" => Number::Port(Side::Either),
                    "sport" => Number::Port(Side::Source),
                    "dport" => Number::Port(Side::Destination),
                    "len" => Number::Length,
                    "ttl" => Number::Ttl,
                    "vlan" => Number::Vlan,
                    "stream" => Number::Stream,
                    "id" => Number::Id,
                    "tcp.seq" => Number::Seq,
                    "tcp.ack" => Number::Ack,
                    "tcp.window" => Number::Window,
                    "time" => Number::Time,
                    _ => return Err(format!("Unknown field: {field}. Use {FIELDS}")),
                };
                let limit = match number {
                    Number::Port(_) | Number::Window => u64::from(u16::MAX),
                    _ => u64::MAX,
                };
                let parse = |text: &str| {
                    text.parse::<u64>()
                        .ok()
                        .filter(|n| *n <= limit)
                        .ok_or_else(|| {
                            if matches!(number, Number::Port(_)) {
                                "Port must be 0–65535".to_string()
                            } else {
                                format!("Invalid number for {field}: {text}")
                            }
                        })
                };
                let (low, high) = match (op, value.split_once('-')) {
                    ("=" | "==" | "!=", Some((low, high))) => (parse(low)?, parse(high)?),
                    ("=" | "==" | "!=", None) => (parse(&value)?, parse(&value)?),
                    ("<", _) => (
                        0,
                        parse(&value)?.checked_sub(1).ok_or("Nothing is below 0")?,
                    ),
                    ("<=", _) => (0, parse(&value)?),
                    (">", _) => (
                        parse(&value)?.checked_add(1).ok_or("Number too large")?,
                        u64::MAX,
                    ),
                    (">=", _) => (parse(&value)?, u64::MAX),
                    _ => return Err(format!("{field} is numeric; use = != < <= > >=")),
                };
                if low > high {
                    return Err(format!("Empty range: {value}"));
                }
                Test::Number(number, low, high)
            }
        };
        // `!=` is NOT(=), so a packet lacking the field matches it.
        Ok(if op == "!=" {
            Node::Not(Box::new(Node::Test(test)))
        } else {
            Node::Test(test)
        })
    }
}

fn protocol(value: &str) -> Result<Protocol, String> {
    Protocol::ALL
        .into_iter()
        .find(|protocol| protocol.name().eq_ignore_ascii_case(value))
        .ok_or_else(|| format!("Unknown protocol: {value}"))
}

fn network(value: &str) -> Result<(IpAddr, u8), String> {
    let invalid = || format!("Invalid IP address: {value}");
    let (address, prefix) = value
        .split_once('/')
        .map_or((value, None), |(a, p)| (a, Some(p)));
    let address = address.parse::<IpAddr>().map_err(|_| invalid())?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse()
            .ok()
            .filter(|p| *p <= bits)
            .ok_or_else(invalid)?,
        None => bits,
    };
    Ok((address, prefix))
}

fn flags(value: &str) -> Result<u8, String> {
    value.split(',').try_fold(0, |mask, name| {
        Ok(mask
            | match name.to_ascii_lowercase().as_str() {
                "fin" => 0x01,
                "syn" => 0x02,
                "rst" => 0x04,
                "psh" => 0x08,
                "ack" => 0x10,
                "urg" => 0x20,
                "ece" => 0x40,
                "cwr" => 0x80,
                _ => return Err(format!("Unknown TCP flag: {name}")),
            })
    })
}

fn analysis(value: &str) -> Result<u8, String> {
    if value.eq_ignore_ascii_case("any") {
        return Ok(u8::MAX);
    }
    diag::NAMES
        .iter()
        .find(|(_, name)| name.eq_ignore_ascii_case(value))
        .map(|(bit, _)| *bit)
        .ok_or_else(|| {
            "tcp.analysis is retransmission, out-of-order, dup-ack, zero-window or any".into()
        })
}

/// Hex bytes such as `dead`, `de:ad` or `0xdead`.
pub fn hex(value: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = value
        .trim_start_matches("0x")
        .bytes()
        .filter(|b| !matches!(b, b':' | b' ' | b'-'))
        .collect();
    let invalid = || format!("Invalid hex bytes: {value} (quote text to search for text)");
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return Err(invalid());
    }
    digits
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(invalid)
        })
        .collect()
}

fn in_network(address: Option<IpAddr>, network: IpAddr, prefix: u8) -> bool {
    let bits = |address: IpAddr| match address {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32u8),
        IpAddr::V6(v6) => (u128::from(v6), 128),
    };
    let Some((address, width)) = address.map(bits) else {
        return false;
    };
    let (network, network_width) = bits(network);
    let shift = u32::from(width) - u32::from(prefix);
    width == network_width
        && address.checked_shr(shift).unwrap_or(0) == network.checked_shr(shift).unwrap_or(0)
}

impl Matcher {
    fn matches(&self, haystack: &[u8]) -> bool {
        match self {
            Self::Regex(regex) => regex.is_match(haystack),
            Self::Contains(needle) => haystack
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle)),
        }
    }
}

impl Test {
    fn matches(&self, packet: &Packet) -> bool {
        let summary = &packet.summary;
        let sides = |side: Side, source: bool, destination: bool| match side {
            Side::Either => source || destination,
            Side::Source => source,
            Side::Destination => destination,
        };
        match self {
            Self::Protocol(Protocol::Ipv4) => {
                matches!(summary.src, Some(IpAddr::V4(_))) && summary.protocol != Protocol::Arp
            }
            Self::Protocol(Protocol::Ipv6) => matches!(summary.src, Some(IpAddr::V6(_))),
            Self::Protocol(Protocol::Tcp) => summary.ip_proto == Some(6),
            Self::Protocol(Protocol::Udp) => summary.ip_proto == Some(17),
            Self::Protocol(protocol) => {
                summary.protocol == *protocol || summary.seen & protocol.bit() != 0
            }
            Self::Address(side, network, prefix) => sides(
                *side,
                in_network(summary.src, *network, *prefix),
                in_network(summary.dst, *network, *prefix),
            ),
            Self::Number(number, low, high) => {
                let within =
                    |value: Option<u64>| value.is_some_and(|v| (*low..=*high).contains(&v));
                match number {
                    Number::Port(side) => sides(
                        *side,
                        within(summary.src_port.map(u64::from)),
                        within(summary.dst_port.map(u64::from)),
                    ),
                    Number::Length => within(Some(u64::from(packet.wire_len))),
                    Number::Ttl => within(summary.ttl.map(u64::from)),
                    Number::Vlan => within(summary.vlan.map(u64::from)),
                    Number::Stream => within(summary.stream.map(u64::from)),
                    Number::Id => within(Some(packet.id)),
                    Number::Seq => within(summary.tcp.map(|t| u64::from(t.seq))),
                    Number::Ack => within(summary.tcp.map(|t| u64::from(t.ack))),
                    Number::Window => within(summary.tcp.map(|t| u64::from(t.window))),
                    Number::Time => within(u64::try_from(packet.timestamp_ns / 1_000_000_000).ok()),
                }
            }
            Self::Flags(mask) => summary.tcp.is_some_and(|t| t.flags & mask == *mask),
            Self::Analysis(mask) => summary.diag & mask != 0,
            Self::Text(Text::Field, matcher) => packet.layers().iter().any(|layer| {
                matcher.matches(layer.label.as_bytes())
                    || layer
                        .fields
                        .iter()
                        .any(|field| matcher.matches(field.label.as_bytes()))
            }),
            Self::Text(text, matcher) => matcher.matches(match text {
                Text::Info => summary.info.as_bytes(),
                Text::Comment => packet.comment.as_deref().unwrap_or_default().as_bytes(),
                Text::Warning => summary.warning.as_deref().unwrap_or_default().as_bytes(),
                Text::Bytes => packet.view().0,
                Text::Payload => packet.payload(),
                Text::Field => &[],
            }),
            Self::Marked => packet.mark,
            Self::HasWarning => summary.warning.is_some(),
            Self::HasComment => packet.comment.is_some(),
            Self::Reassembled => packet.reassembled.is_some(),
            Self::Named(named, compare) => named
                .values(packet)
                .iter()
                .any(|value| compare.matches(value)),
        }
    }
}

impl Node {
    fn matches(&self, packet: &Packet) -> bool {
        match self {
            Self::Or(left, right) => left.matches(packet) || right.matches(packet),
            Self::And(left, right) => left.matches(packet) && right.matches(packet),
            Self::Not(node) => !node.matches(packet),
            Self::Test(test) => test.matches(packet),
        }
    }
}

impl Filter {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > 1024 {
            return Err("Filter is limited to 1024 bytes".into());
        }
        let tokens = tokens(input)?;
        if tokens.is_empty() {
            return Ok(Self::default());
        }
        let mut parser = Parser {
            tokens,
            position: 0,
        };
        let root = parser.or(0)?;
        match parser.peek() {
            None => Ok(Self { root: Some(root) }),
            Some(_) => Err("Unexpected closing parenthesis".into()),
        }
    }

    /// Matches packets whose bytes contain `needle` (ASCII case-insensitive).
    pub fn containing(needle: &[u8]) -> Self {
        let needle = needle.to_ascii_lowercase();
        Self {
            root: Some(Node::Test(Test::Text(
                Text::Bytes,
                Matcher::Contains(needle),
            ))),
        }
    }

    /// Both filters must match.
    pub fn and(self, other: &Self) -> Self {
        Self {
            root: match (self.root, other.root.clone()) {
                (Some(left), Some(right)) => Some(Node::And(Box::new(left), Box::new(right))),
                (left, right) => left.or(right),
            },
        }
    }

    pub fn matches(&self, packet: &Packet) -> bool {
        self.root.as_ref().is_none_or(|root| root.matches(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{Summary, Tcp};

    fn packet(summary: Summary) -> Packet {
        let mut packet = Packet::new(7, 0, 120, 999, b"\x00GET /Index\xff".to_vec().into());
        packet.summary = summary;
        packet
    }

    fn tcp() -> Packet {
        packet(Summary {
            protocol: Protocol::Tls,
            ip_proto: Some(6),
            src: Some("192.0.2.1".parse().unwrap()),
            dst: Some("2001:db8::9".parse().unwrap()),
            src_port: Some(51000),
            dst_port: Some(443),
            ttl: Some(64),
            info: "Client Hello · SNI example.com".into(),
            tcp: Some(Tcp {
                seq: 1,
                ack: 0,
                flags: 0x12,
                window: 0,
            }),
            payload: (1, 11),
            diag: diag::ZERO_WINDOW,
            ..Summary::default()
        })
    }

    fn matches(filter: &str, packet: &Packet) -> bool {
        Filter::parse(filter)
            .unwrap_or_else(|error| panic!("{filter}: {error}"))
            .matches(packet)
    }

    #[test]
    fn combines_predicates_and_rejects_invalid_input() {
        let packet = tcp();
        assert!(matches("proto=tcp port=443 src=192.0.2.1", &packet));
        assert!(!matches("port=80", &packet));
        for bad in [
            "tcp",
            "port=65536",
            "addr=no",
            "proto=nope",
            "foo=bar",
            "(port=1",
            "port=1)",
            "port=",
            "not",
            "port=9-1",
            "addr=192.0.2.1/33",
            "info~(",
            "bytes contains xyz",
            "proto<tcp",
            "tcp.flags=syn,nope",
            "port=1 or",
            "\"open",
        ] {
            assert!(Filter::parse(bad).is_err(), "{bad}");
        }
        assert!(Filter::parse(&"(".repeat(64))
            .unwrap_err()
            .contains("deeply"));
    }

    #[test]
    fn boolean_operators_and_precedence() {
        let packet = tcp();
        assert!(matches("port=80 or port=443", &packet));
        assert!(matches("port=80 || proto=tls && port=443", &packet));
        assert!(!matches("(port=80 or port=443) and proto=udp", &packet));
        assert!(matches("not port=80 !proto=udp", &packet));
        assert!(matches("NOT (port=80 OR proto=udp)", &packet));
        assert!(matches("port!=80", &packet));
        assert!(!matches("port!=443", &packet));
    }

    #[test]
    fn subnets_numbers_ranges_and_protocol_fields() {
        let packet = tcp();
        assert!(matches("src=192.0.2.0/24 dst=2001:db8::/32", &packet));
        assert!(!matches("addr=198.51.100.0/24", &packet));
        assert!(matches("addr=0.0.0.0/0", &packet));
        assert!(matches(
            "dport>=443 dport<444 sport>50000 port=440-450",
            &packet
        ));
        assert!(!matches("sport<=1024", &packet));
        assert!(matches("len>100 len<=120 ttl=64 id=7", &packet));
        assert!(!matches("vlan=1", &packet));
        assert!(matches("tcp.flags=syn,ack tcp.window=0 tcp.seq=1", &packet));
        assert!(!matches("tcp.flags=fin", &packet));
        assert!(matches(
            "tcp.analysis=zero-window tcp.analysis=any",
            &packet
        ));
        assert!(!matches("tcp.analysis=retransmission", &packet));
    }

    #[test]
    fn text_bytes_and_regex_matching() {
        let mut packet = tcp();
        assert!(matches("info contains \"sni EXAMPLE\"", &packet));
        assert!(matches("info~\"hello.*example\\.com$\"", &packet));
        assert!(matches("bytes contains \"get /index\"", &packet));
        assert!(matches("bytes contains 47:45:54", &packet));
        assert!(matches("bytes contains 0xff", &packet));
        assert!(matches("payload~\"^GET /[A-Z]\"", &packet));
        assert!(!matches("payload contains ff", &packet));
        assert!(!matches(
            "marked or comment or warning or reassembled",
            &packet
        ));
        packet.mark = true;
        packet.comment = Some("Suspicious".into());
        assert!(matches("marked comment~susp", &packet));
        assert!(Filter::containing(b"INDEX").matches(&packet));
    }

    #[test]
    fn named_fields_compare_by_type() {
        // IPv4 TCP segment carrying an HTTP request.
        let mut bytes = vec![0x45, 0, 0, 77, 0, 0, 0, 0, 64, 6, 0, 0];
        bytes.extend([192, 0, 2, 1, 192, 0, 2, 2, 0x13, 0x88, 0, 80]);
        bytes.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x20, 0, 0, 0, 0, 0]);
        bytes.extend(b"GET /a HTTP/1.1\r\nHost: Example.com\r\n\r\n");
        let packet = Packet::new(1, 0, bytes.len() as u32, 101, bytes.into());
        for filter in [
            "http.host == example.com",
            "http.host contains \"ample\"",
            "http.host~\"^ex.*com$\"",
            "http.host",
            "http.request.method == GET",
            "http.request.uri == /a",
            "ip.ttl == 64 ip.ttl >= 64 ip.ttl < 65 ipv4.ttl=0x40",
            "tcp.srcport == 5000 tcp.window > 8000",
            "ip.src == 192.0.2.1",
            "http.host != other.example",
            "not http.response.code",
        ] {
            assert!(matches(filter, &packet), "{filter}");
        }
        for filter in [
            "http.host == example",
            "ip.ttl > 64",
            "dns.qry.name",
            "tcp.window < 10",
        ] {
            assert!(!matches(filter, &packet), "{filter}");
        }
        for bad in [
            "nosuch.field == 1",
            "http.",
            "ip.ttl > many",
            "http.host ~ \"(\"",
        ] {
            assert!(Filter::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn application_protocols_still_match_their_transport() {
        let dns = packet(Summary {
            protocol: Protocol::Dns,
            ip_proto: Some(17),
            ..Summary::default()
        });
        assert!(matches("proto=udp proto=dns", &dns));
        assert!(matches("proto=tcp proto=tls", &tcp()));
        assert!(matches("", &dns));
    }
}
