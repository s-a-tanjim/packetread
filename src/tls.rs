//! TLS decryption of a reconstructed stream using an NSS key log
//! (`SSLKEYLOGFILE`) or, for RSA key exchange, the server's private key.
//! Supports TLS 1.3 and, for TLS 1.2, the AEAD and AES-CBC cipher suites.
//!
//! Not handled: RC4 and 3DES suites, CBC before TLS 1.2, 0-RTT early data, and hello messages split across
//! records. Records that fail authentication are skipped and counted, never
//! shown.
use crate::{
    crypto::{cbc_decrypt, Aes},
    decode::tls::{hello, is_record, Reader},
    follow::{Chunk, Stream},
};
use ring::{aead, digest, hkdf, hmac};

use std::{collections::HashMap, fs::File, io::Read, path::Path, sync::Arc};

const MAX_KEYLOG_BYTES: u64 = 64 * 1024 * 1024;
/// ServerHello.random of a HelloRetryRequest (RFC 8446 §4.1.3).
const RETRY: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Label {
    Master,
    ClientHandshake,
    ServerHandshake,
    ClientTraffic,
    ServerTraffic,
}

/// Secrets keyed by label and client random.
#[derive(Default)]
pub struct KeyLog {
    secrets: HashMap<(Label, [u8; 32]), Vec<u8>>,
}

impl std::fmt::Debug for KeyLog {
    // Secrets never appear in debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyLog({} secrets)", self.secrets.len())
    }
}

impl KeyLog {
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let mut text = String::new();
        File::open(path)?
            .take(MAX_KEYLOG_BYTES)
            .read_to_string(&mut text)?;
        Ok(Self::parse(&text))
    }

    /// Unknown labels and malformed lines are ignored, as other tools do.
    pub fn parse(text: &str) -> Self {
        let mut secrets = HashMap::new();
        for line in text.lines() {
            let mut words = line.split_whitespace();
            let (Some(label), Some(random), Some(secret)) =
                (words.next(), words.next(), words.next())
            else {
                continue;
            };
            let label = match label {
                "CLIENT_RANDOM" => Label::Master,
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Label::ClientHandshake,
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Label::ServerHandshake,
                "CLIENT_TRAFFIC_SECRET_0" => Label::ClientTraffic,
                "SERVER_TRAFFIC_SECRET_0" => Label::ServerTraffic,
                _ => continue,
            };
            let (Ok(random), Ok(secret)) = (crate::filter::hex(random), crate::filter::hex(secret))
            else {
                continue;
            };
            if let (Ok(random), true) = (<[u8; 32]>::try_from(random), secret.len() <= 64) {
                secrets.insert((label, random), secret);
            }
        }
        Self { secrets }
    }

    /// `keylog`, or an empty log when only server private keys were loaded
    /// (`crypto::add_tls_key`), so sessions with RSA key exchange decrypt.
    pub fn or_private_keys(keylog: Option<Arc<Self>>) -> Option<Arc<Self>> {
        keylog.or_else(|| crate::crypto::has_tls_keys().then(Arc::default))
    }

    /// TLS 1.3 secrets of a QUIC connection: client and server handshake,
    /// then client and server application traffic.
    pub(crate) fn quic_secrets(&self, client_random: [u8; 32]) -> [Option<&Vec<u8>>; 4] {
        [
            Label::ClientHandshake,
            Label::ServerHandshake,
            Label::ClientTraffic,
            Label::ServerTraffic,
        ]
        .map(|label| self.secrets.get(&(label, client_random)))
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Copy)]
struct Suite {
    aead: &'static aead::Algorithm,
    hkdf: hkdf::Algorithm,
    hmac: hmac::Algorithm,
    /// AES-CBC suites: key length and record MAC (`aead` is then unused).
    cbc: Option<(usize, hmac::Algorithm)>,
}

fn suite(id: u16) -> Option<Suite> {
    let sha256 = (hkdf::HKDF_SHA256, hmac::HMAC_SHA256);
    let sha384 = (hkdf::HKDF_SHA384, hmac::HMAC_SHA384);
    let sha1 = hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY;
    let cbc = match id {
        0x002f | 0x0033 | 0xc009 | 0xc013 => Some((16, sha1, sha256)),
        0x0035 | 0x0039 | 0xc00a | 0xc014 => Some((32, sha1, sha256)),
        0x003c | 0x0067 | 0xc023 | 0xc027 => Some((16, hmac::HMAC_SHA256, sha256)),
        0x003d | 0x006b => Some((32, hmac::HMAC_SHA256, sha256)),
        0xc024 | 0xc028 => Some((32, hmac::HMAC_SHA384, sha384)),
        _ => None,
    };
    if let Some((key, mac, (hkdf, hmac))) = cbc {
        return Some(Suite {
            aead: &aead::AES_128_GCM,
            hkdf,
            hmac,
            cbc: Some((key, mac)),
        });
    }
    let (aead, (hkdf, hmac)) = match id {
        0x1301 | 0x009c | 0x009e | 0xc02b | 0xc02f => (&aead::AES_128_GCM, sha256),
        0x1302 | 0x009d | 0x009f | 0xc02c | 0xc030 => (&aead::AES_256_GCM, sha384),
        0x1303 | 0xcca8 | 0xcca9 | 0xccaa => (&aead::CHACHA20_POLY1305, sha256),
        _ => return None,
    };
    Some(Suite {
        aead,
        hkdf,
        hmac,
        cbc: None,
    })
}

struct Length(usize);
impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label with an empty context (RFC 8446 §7.1).
pub(crate) fn expand_label(
    algorithm: hkdf::Algorithm,
    secret: &[u8],
    label: &str,
    length: usize,
) -> Option<Vec<u8>> {
    let label = format!("tls13 {label}");
    let info = [
        &(length as u16).to_be_bytes()[..],
        &[label.len() as u8],
        label.as_bytes(),
        &[0],
    ];
    let mut out = vec![0; length];
    hkdf::Prk::new_less_safe(algorithm, secret)
        .expand(&info, Length(length))
        .and_then(|okm| okm.fill(&mut out))
        .ok()?;
    Some(out)
}

/// The TLS 1.2 pseudorandom function (RFC 5246 §5).
fn prf(
    algorithm: hmac::Algorithm,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Vec<u8> {
    let key = hmac::Key::new(algorithm, secret);
    let seed = [label, seed].concat();
    let mut a = hmac::sign(&key, &seed).as_ref().to_vec();
    let mut out = Vec::new();
    while out.len() < length {
        out.extend(hmac::sign(&key, &[&a[..], &seed].concat()).as_ref());
        a = hmac::sign(&key, &a).as_ref().to_vec();
    }
    out.truncate(length);
    out
}

struct Keys {
    key: aead::LessSafeKey,
    iv: Vec<u8>,
    sequence: u64,
}

impl Keys {
    fn new(suite: Suite, key: &[u8], iv: &[u8]) -> Option<Self> {
        Some(Self {
            key: aead::LessSafeKey::new(aead::UnboundKey::new(suite.aead, key).ok()?),
            iv: iv.to_vec(),
            sequence: 0,
        })
    }

    fn traffic(suite: Suite, secret: &[u8]) -> Option<Self> {
        let key = expand_label(suite.hkdf, secret, "key", suite.aead.key_len())?;
        Self::new(suite, &key, &expand_label(suite.hkdf, secret, "iv", 12)?)
    }

    /// Authenticates and decrypts one record body; advances the sequence on success.
    fn open(&mut self, nonce: [u8; 12], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let mut buffer = ciphertext.to_vec();
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let length = self
            .key
            .open_in_place(nonce, aead::Aad::from(aad), &mut buffer)
            .ok()?
            .len();
        buffer.truncate(length);
        self.sequence += 1;
        Some(buffer)
    }

    /// The 12-byte IV XORed with the record sequence number.
    fn counter_nonce(&self) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&self.iv);
        for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        nonce
    }
}

/// Keys of one direction of a TLS 1.2 AES-CBC session.
struct Cbc {
    aes: Aes,
    mac: hmac::Key,
    sequence: u64,
    /// Encrypt-then-MAC (RFC 7366): the MAC covers the ciphertext.
    etm: bool,
}

impl Cbc {
    /// Decrypts one record, checking its padding and MAC.
    fn open(&mut self, record: &[u8]) -> Option<Vec<u8>> {
        let mac_length = self.mac.algorithm().digest_algorithm().output_len();
        let mut signed = self.sequence.to_be_bytes().to_vec();
        signed.extend(&record[..3]);
        let body = &record[5..];
        let content = if self.etm {
            let (sealed, mac) = body.split_at_checked(body.len().checked_sub(mac_length)?)?;
            signed.extend((sealed.len() as u16).to_be_bytes());
            signed.extend(sealed);
            if hmac::sign(&self.mac, &signed).as_ref() != mac {
                return None;
            }
            let (iv, cipher) = sealed.split_at_checked(16)?;
            let mut plain = cbc_decrypt(&self.aes, iv, cipher)?;
            let padding = usize::from(*plain.last()?) + 1;
            plain.truncate(plain.len().checked_sub(padding)?);
            plain
        } else {
            let (iv, cipher) = body.split_at_checked(16)?;
            let mut plain = cbc_decrypt(&self.aes, iv, cipher)?;
            let padding = usize::from(*plain.last()?) + 1;
            let length = plain.len().checked_sub(padding + mac_length)?;
            signed.extend((length as u16).to_be_bytes());
            signed.extend(&plain[..length]);
            if hmac::sign(&self.mac, &signed).as_ref() != &plain[length..length + mac_length] {
                return None;
            }
            plain.truncate(length);
            plain
        };
        self.sequence += 1;
        Some(content)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Plain,
    Handshake,
    Application,
}

struct Direction {
    buffer: Vec<u8>,
    handshake: Vec<u8>,
    phase: Phase,
    keys: Option<Keys>,
    cbc: Option<Cbc>,
    /// Current TLS 1.3 traffic secret, kept for KeyUpdate.
    secret: Option<Vec<u8>>,
}

/// Incremental decryption of one TLS connection: feed complete records in
/// order, per direction, and collect the application data they carry.
pub struct Decryptor {
    log: Arc<KeyLog>,
    client_random: Option<[u8; 32]>,
    server_random: [u8; 32],
    suite: Option<Suite>,
    tls13: bool,
    version: u16,
    /// The server agreed to the extended master secret, encrypt-then-MAC.
    ems: bool,
    etm: bool,
    /// Handshake messages up to the ClientKeyExchange, for that secret.
    transcript: Vec<u8>,
    /// Master secret recovered with an RSA private key.
    master: Option<Vec<u8>>,
    directions: [Direction; 2],
    failed: u64,
    out: Vec<Chunk>,
}

/// Pops complete handshake messages (type, body) from `buffer`.
fn messages(buffer: &mut Vec<u8>) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while buffer.len() >= 4 {
        let length =
            (usize::from(buffer[1]) << 16) | (usize::from(buffer[2]) << 8) | usize::from(buffer[3]);
        if buffer.len() < 4 + length {
            break;
        }
        let message: Vec<u8> = buffer.drain(..4 + length).collect();
        out.push((message[0], message[4..].to_vec()));
    }
    out
}

impl Decryptor {
    pub fn new(log: Arc<KeyLog>) -> Self {
        let direction = || Direction {
            buffer: Vec::new(),
            handshake: Vec::new(),
            phase: Phase::Plain,
            keys: None,
            cbc: None,
            secret: None,
        };
        Self {
            log,
            client_random: None,
            server_random: [0; 32],
            suite: None,
            tls13: false,
            version: 0,
            ems: false,
            etm: false,
            transcript: Vec::new(),
            master: None,
            directions: [direction(), direction()],
            failed: 0,
            out: Vec::new(),
        }
    }

    /// Processes one complete record (header included) and returns the
    /// application data decrypted so far. Malformed or unsupported sessions
    /// simply yield nothing.
    pub fn feed(&mut self, from_client: bool, record: &[u8]) -> Vec<Chunk> {
        if record.len() >= 5 {
            let _ = self.record(from_client, record);
        }
        std::mem::take(&mut self.out)
    }

    fn secret(&self, label: Label) -> Option<&Vec<u8>> {
        let logged = self.log.secrets.get(&(label, self.client_random?));
        logged.or(self.master.as_ref().filter(|_| label == Label::Master))
    }

    /// RSA key exchange: recover the master secret with a private key.
    fn client_key_exchange(&mut self, body: &[u8]) -> Option<()> {
        if self.tls13 || self.secret(Label::Master).is_some() {
            return None;
        }
        let premaster = crate::crypto::tls_premaster(Reader(body).vec16()?)?;
        let suite = self.suite?;
        self.master = Some(if self.ems {
            let hash = digest::digest(suite.hmac.digest_algorithm(), &self.transcript);
            prf(
                suite.hmac,
                &premaster,
                b"extended master secret",
                hash.as_ref(),
                48,
            )
        } else {
            let seed = [self.client_random?, self.server_random].concat();
            prf(suite.hmac, &premaster, b"master secret", &seed, 48)
        });
        Some(())
    }

    fn traffic_keys(&mut self, from_client: bool, phase: Phase) {
        let label = match (from_client, phase == Phase::Handshake) {
            (true, true) => Label::ClientHandshake,
            (false, true) => Label::ServerHandshake,
            (true, false) => Label::ClientTraffic,
            (false, false) => Label::ServerTraffic,
        };
        let secret = self.secret(label).cloned();
        let keys = secret
            .as_ref()
            .zip(self.suite)
            .and_then(|(secret, suite)| Keys::traffic(suite, secret));
        let direction = &mut self.directions[usize::from(!from_client)];
        (direction.phase, direction.keys, direction.secret) = (phase, keys, secret);
    }

    fn record(&mut self, from_client: bool, record: &[u8]) -> Result<(), String> {
        let index = usize::from(!from_client);
        let (kind, body) = (record[0], &record[5..]);
        match self.directions[index].phase {
            Phase::Plain if kind == 22 => {
                if self.directions[index].handshake.len() + body.len() > 1 << 17 {
                    return Err("Oversized TLS handshake".into());
                }
                self.directions[index].handshake.extend(body);
                for (kind, body) in messages(&mut self.directions[index].handshake) {
                    if self.transcript.len() + body.len() <= 1 << 18 {
                        self.transcript.push(kind);
                        self.transcript
                            .extend(&(body.len() as u32).to_be_bytes()[1..]);
                        self.transcript.extend(&body);
                    }
                    if kind == 16 && from_client {
                        self.client_key_exchange(&body);
                    }
                    self.hello(from_client, kind, &body)?;
                }
            }
            Phase::Plain if kind == 20 && !self.tls13 => self.change_cipher_spec(from_client),
            Phase::Plain => {}
            _ if self.tls13 => {
                if kind == 23 {
                    self.record13(from_client, record);
                }
            }
            _ => {
                let direction = &mut self.directions[index];
                let cbc = direction.cbc.as_mut().and_then(|cbc| cbc.open(record));
                let keys = direction.keys.as_mut();
                let plain = cbc.or_else(|| {
                    let keys = keys?;
                    let chacha = keys.iv.len() == 12;
                    let (nonce, ciphertext) = if chacha {
                        (keys.counter_nonce(), body)
                    } else {
                        let (explicit, ciphertext) = body.split_at_checked(8)?;
                        let mut nonce = [0; 12];
                        nonce[..4].copy_from_slice(&keys.iv);
                        nonce[4..].copy_from_slice(explicit);
                        (nonce, ciphertext)
                    };
                    let length = ciphertext.len().checked_sub(16)? as u16;
                    let mut aad = keys.sequence.to_be_bytes().to_vec();
                    aad.extend(&record[..3]);
                    aad.extend(length.to_be_bytes());
                    keys.open(nonce, &aad, ciphertext)
                });
                match plain {
                    Some(data) if kind == 23 => self.out.push(Chunk { from_client, data }),
                    Some(_) => {}
                    None => self.failed += 1,
                }
            }
        }
        Ok(())
    }

    fn hello(&mut self, from_client: bool, kind: u8, body: &[u8]) -> Result<(), String> {
        let Some(hello) = Some(kind)
            .filter(|k| *k == if from_client { 1 } else { 2 })
            .and_then(|k| hello(k, body))
        else {
            return Ok(());
        };
        if from_client {
            self.client_random = Some(hello.random);
        } else if hello.random != RETRY {
            let cipher = hello.cipher.unwrap_or(0);
            self.suite = Some(suite(cipher).ok_or_else(|| {
                format!(
                    "Unsupported cipher suite: {}",
                    crate::decode::tls::cipher_name(cipher)
                )
            })?);
            self.server_random = hello.random;
            self.tls13 = hello.version == 0x0304;
            self.version = hello.version;
            self.ems = hello.ems;
            self.etm = hello.etm;
            if self.tls13 {
                self.traffic_keys(true, Phase::Handshake);
                self.traffic_keys(false, Phase::Handshake);
            }
        }
        Ok(())
    }

    /// TLS 1.2: records after ChangeCipherSpec use keys from the master secret.
    fn change_cipher_spec(&mut self, from_client: bool) {
        if let Some((suite, (key, mac))) = self.suite.and_then(|s| Some((s, s.cbc?))) {
            let cbc = self
                .secret(Label::Master)
                .zip(self.client_random)
                .filter(|_| self.version == 0x0303)
                .and_then(|(master, client_random)| {
                    let hash = mac.digest_algorithm().output_len();
                    let seed = [self.server_random, client_random].concat();
                    let block = prf(
                        suite.hmac,
                        master,
                        b"key expansion",
                        &seed,
                        2 * hash + 2 * key,
                    );
                    let (mac_at, key_at) = if from_client {
                        (0, 2 * hash)
                    } else {
                        (hash, 2 * hash + key)
                    };
                    Some(Cbc {
                        aes: Aes::new(&block[key_at..key_at + key])?,
                        mac: hmac::Key::new(mac, &block[mac_at..mac_at + hash]),
                        sequence: 0,
                        etm: self.etm,
                    })
                });
            let direction = &mut self.directions[usize::from(!from_client)];
            (direction.phase, direction.cbc) = (Phase::Application, cbc);
            return;
        }
        let keys = self
            .secret(Label::Master)
            .zip(self.suite)
            .and_then(|(master, suite)| {
                let (key, iv) = (
                    suite.aead.key_len(),
                    if suite.aead == &aead::CHACHA20_POLY1305 {
                        12
                    } else {
                        4
                    },
                );
                let seed = [self.server_random, self.client_random?].concat();
                let block = prf(
                    suite.hmac,
                    master,
                    b"key expansion",
                    &seed,
                    2 * key + 2 * iv,
                );
                let (key_at, iv_at) = if from_client {
                    (0, 2 * key)
                } else {
                    (key, 2 * key + iv)
                };
                Keys::new(
                    suite,
                    &block[key_at..key_at + key],
                    &block[iv_at..iv_at + iv],
                )
            });
        let direction = &mut self.directions[usize::from(!from_client)];
        (direction.phase, direction.keys) = (Phase::Application, keys);
    }

    fn record13(&mut self, from_client: bool, record: &[u8]) {
        let index = usize::from(!from_client);
        let open = |keys: &mut Keys| keys.open(keys.counter_nonce(), &record[..5], &record[5..]);
        let mut plain = self.directions[index].keys.as_mut().and_then(open);
        if plain.is_none() && self.directions[index].phase == Phase::Handshake {
            // The log may lack handshake secrets; application keys start at sequence 0.
            let secret = self
                .secret(if from_client {
                    Label::ClientTraffic
                } else {
                    Label::ServerTraffic
                })
                .cloned();
            let keys = secret
                .as_ref()
                .zip(self.suite)
                .and_then(|(secret, suite)| Keys::traffic(suite, secret));
            if let Some(mut keys) = keys {
                plain = open(&mut keys);
                if plain.is_some() {
                    let direction = &mut self.directions[index];
                    (direction.phase, direction.keys, direction.secret) =
                        (Phase::Application, Some(keys), secret);
                }
            }
        }
        let Some(mut data) = plain else {
            self.failed += 1;
            return;
        };
        // TLSInnerPlaintext: content, content type, zero padding.
        while data.last() == Some(&0) {
            data.pop();
        }
        match data.pop() {
            Some(23) if !data.is_empty() => self.out.push(Chunk { from_client, data }),
            Some(22) if self.directions[index].handshake.len() + data.len() <= 1 << 17 => {
                self.directions[index].handshake.extend(data);
                for (kind, _) in messages(&mut self.directions[index].handshake) {
                    match (kind, self.directions[index].phase) {
                        (20, Phase::Handshake) => {
                            self.traffic_keys(from_client, Phase::Application)
                        }
                        (24, Phase::Application) => self.key_update(index),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn key_update(&mut self, index: usize) {
        let Some(suite) = self.suite else { return };
        let direction = &mut self.directions[index];
        let length = suite.hmac.digest_algorithm().output_len();
        direction.secret = direction
            .secret
            .as_ref()
            .and_then(|s| expand_label(suite.hkdf, s, "traffic upd", length));
        direction.keys = direction
            .secret
            .as_ref()
            .and_then(|s| Keys::traffic(suite, s));
    }
}

/// Decrypts the application data of a followed TLS stream. The result has
/// the same endpoints with plaintext chunks.
pub fn decrypt(stream: &Stream, log: &Arc<KeyLog>) -> Result<Stream, String> {
    let mut session = Decryptor::new(Arc::clone(log));
    for chunk in &stream.chunks {
        let index = usize::from(!chunk.from_client);
        session.directions[index].buffer.extend(&chunk.data);
        loop {
            let buffer = &mut session.directions[index].buffer;
            if buffer.len() < 5 {
                break;
            }
            if !is_record(buffer) {
                // Not TLS, or the stream lost bytes: stop reading this direction.
                buffer.clear();
                break;
            }
            let length = 5 + (usize::from(buffer[3]) << 8 | usize::from(buffer[4]));
            if buffer.len() < length {
                break;
            }
            let record: Vec<u8> = buffer.drain(..length).collect();
            session.record(chunk.from_client, &record)?;
        }
    }
    let random = session
        .client_random
        .ok_or("No TLS ClientHello in this stream")?;
    if session.suite.is_none() {
        return Err("No TLS ServerHello in this stream".into());
    }
    if session.master.is_none() && !log.secrets.keys().any(|(_, r)| *r == random) {
        return Err("The key log has no secrets for this TLS session".into());
    }
    if session.out.is_empty() && session.failed > 0 {
        return Err(format!("{} TLS records failed to decrypt", session.failed));
    }
    Ok(Stream {
        id: stream.id,
        tcp: stream.tcp,
        client: stream.client,
        server: stream.server,
        chunks: session.out,
        missing: stream.missing,
        truncated: stream.truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_log_ignores_malformed_lines() {
        let random = "ab".repeat(32);
        let log = KeyLog::parse(&format!(
            "# comment\nCLIENT_RANDOM {random} {}\nCLIENT_RANDOM short 00\nBOGUS {random} 00\n\
             SERVER_TRAFFIC_SECRET_0 {random} zz\nCLIENT_TRAFFIC_SECRET_0 {random} {}\n",
            "01".repeat(48),
            "02".repeat(32)
        ));
        assert_eq!(log.len(), 2);
        assert_eq!(log.secrets[&(Label::Master, [0xab; 32])], vec![1; 48]);
    }

    #[test]
    fn derives_rfc8448_traffic_keys() {
        // RFC 8448 §3: client handshake traffic secret → write key and IV.
        let secret =
            crate::filter::hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
                .unwrap();
        let hex = |bytes: Vec<u8>| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let key = expand_label(hkdf::HKDF_SHA256, &secret, "key", 16).unwrap();
        let iv = expand_label(hkdf::HKDF_SHA256, &secret, "iv", 12).unwrap();
        assert_eq!(hex(key), "dbfaa693d1762c5b666af5d950258d01");
        assert_eq!(hex(iv), "5bd3c71b836e0b76bb73265f");
    }

    #[test]
    fn non_tls_streams_are_rejected() {
        let stream = Stream {
            chunks: vec![Chunk {
                from_client: true,
                data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            }],
            ..Stream::default()
        };
        assert!(decrypt(&stream, &Arc::new(KeyLog::default()))
            .unwrap_err()
            .contains("ClientHello"));
    }
}
