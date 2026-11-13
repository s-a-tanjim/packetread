//! Decryption with keys the user supplies: Kerberos (keytab, AES etypes 17
//! and 18), IPsec ESP (security associations) and WPA2-PSK CCMP (passphrase
//! and network name). Keys are process-wide, like Decode As rules.
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use ring::{aead, hmac, pbkdf2};
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, Pkcs1v15Encrypt, RsaPrivateKey};
use std::{num::NonZeroU32, sync::RwLock};

pub(crate) enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    pub fn new(key: &[u8]) -> Option<Self> {
        Some(match key.len() {
            16 => Self::A128(aes::Aes128::new_from_slice(key).ok()?),
            24 => Self::A192(aes::Aes192::new_from_slice(key).ok()?),
            32 => Self::A256(aes::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        })
    }
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::A128(aes) => aes.encrypt_block(block),
            Self::A192(aes) => aes.encrypt_block(block),
            Self::A256(aes) => aes.encrypt_block(block),
        }
    }
    pub fn decrypt(&self, block: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::A128(aes) => aes.decrypt_block(block),
            Self::A192(aes) => aes.decrypt_block(block),
            Self::A256(aes) => aes.decrypt_block(block),
        }
    }
}

fn xor(target: &mut [u8], other: &[u8]) {
    for (byte, other) in target.iter_mut().zip(other) {
        *byte ^= other;
    }
}

/// AES-CBC without padding removal; `data` must be whole blocks.
pub(crate) fn cbc_decrypt(aes: &Aes, iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 16 || !data.len().is_multiple_of(16) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut previous = iv;
    for chunk in data.as_chunks::<16>().0 {
        let mut block = *chunk;
        aes.decrypt(&mut block);
        xor(&mut block, previous);
        out.extend(block);
        previous = chunk;
    }
    Some(out)
}

/// ESP security association: SPI, cipher and key material.
struct EspSa {
    spi: u32,
    gcm: bool,
    key: Vec<u8>,
    icv: usize,
}

#[derive(Default)]
struct Secrets {
    kerberos: Vec<Vec<u8>>,
    esp: Vec<EspSa>,
    /// WPA pairwise master keys.
    wpa: Vec<[u8; 32]>,
    /// Server private keys for TLS sessions with RSA key exchange.
    tls: Vec<RsaPrivateKey>,
}

static SECRETS: RwLock<Secrets> = RwLock::new(Secrets {
    kerberos: Vec::new(),
    esp: Vec::new(),
    wpa: Vec::new(),
    tls: Vec::new(),
});

fn secrets() -> std::sync::RwLockReadGuard<'static, Secrets> {
    SECRETS.read().unwrap_or_else(|e| e.into_inner())
}
fn secrets_mut() -> std::sync::RwLockWriteGuard<'static, Secrets> {
    SECRETS.write().unwrap_or_else(|e| e.into_inner())
}

/// Adds a PEM RSA private key (PKCS#8 or PKCS#1) for TLS sessions that
/// used RSA key exchange.
pub fn add_tls_key(pem: &str) -> Result<(), String> {
    if pem.len() > 1 << 16 {
        return Err("Private key file is too large".into());
    }
    let key = RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|_| "Not an unencrypted PEM RSA private key")?;
    secrets_mut().tls.push(key);
    Ok(())
}

pub(crate) fn has_tls_keys() -> bool {
    !secrets().tls.is_empty()
}

/// The premaster secret of an RSA ClientKeyExchange, if a loaded key opens it.
pub(crate) fn tls_premaster(encrypted: &[u8]) -> Option<Vec<u8>> {
    secrets()
        .tls
        .iter()
        .find_map(|key| key.decrypt(Pkcs1v15Encrypt, encrypted).ok())
        .filter(|premaster| premaster.len() == 48)
}

/// Loads the AES keys of an MIT keytab (format 0x0502); returns their count.
pub fn load_keytab(data: &[u8]) -> Result<usize, String> {
    if data.len() > 1 << 20 || !data.starts_with(&[5, 2]) {
        return Err("Not a keytab file (expected format 0x0502 under 1 MiB)".into());
    }
    let mut cursor = 2;
    let mut keys = Vec::new();
    // Every entry consumes at least its four-byte size.
    while let Some(size) = data.get(cursor..cursor + 4) {
        let size = i32::from_be_bytes(size.try_into().unwrap_or_default());
        cursor += 4;
        let Some(entry) = data.get(cursor..cursor + size.unsigned_abs() as usize) else {
            return Err("Truncated keytab entry".into());
        };
        cursor += entry.len();
        if size <= 0 {
            continue; // A deleted entry.
        }
        let key = (|| {
            let mut reader = crate::decode::tls::Reader(entry);
            let components = reader.u16()?;
            for _ in 0..=components {
                reader.vec16()?; // The realm, then each name component.
            }
            reader.take(4 + 4 + 1)?; // Name type, timestamp, 8-bit key version.
            let etype = reader.u16()?;
            Some((etype, reader.vec16()?.to_vec()))
        })()
        .ok_or("Malformed keytab entry")?;
        if matches!((key.0, key.1.len()), (17, 16) | (18, 32)) {
            keys.push(key.1);
        }
    }
    let count = keys.len();
    secrets_mut().kerberos.extend(keys);
    Ok(count)
}

/// RFC 3961 n-fold.
fn nfold(input: &[u8], size: usize) -> Vec<u8> {
    let gcd = |mut a: usize, mut b: usize| {
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    };
    let length = input.len();
    let lcm = length * size / gcd(length, size);
    let mut out = vec![0u8; size];
    let mut carry = 0u32;
    for i in (0..lcm).rev() {
        let bit = ((length << 3) - 1
            + ((length << 3) + 13) * (i / length)
            + ((length - (i % length)) << 3))
            % (length << 3);
        let pair = u32::from(input[((length - 1) - (bit >> 3)) % length]) << 8
            | u32::from(input[(length - (bit >> 3)) % length]);
        carry += (pair >> ((bit & 7) + 1)) & 0xff;
        carry += u32::from(out[i % size]);
        out[i % size] = carry as u8;
        carry >>= 8;
    }
    for byte in out.iter_mut().rev() {
        if carry == 0 {
            break;
        }
        carry += u32::from(*byte);
        *byte = carry as u8;
        carry >>= 8;
    }
    out
}

/// RFC 3961 key derivation for the AES encryption types.
fn derive(key: &[u8], constant: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(key)?;
    let mut block: [u8; 16] = nfold(constant, 16).try_into().ok()?;
    let mut out = Vec::new();
    while out.len() < key.len() {
        aes.encrypt(&mut block);
        out.extend(block);
    }
    out.truncate(key.len());
    Some(out)
}

/// AES-CBC with ciphertext stealing (RFC 3962), zero IV.
fn cts_decrypt(aes: &Aes, data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 16 {
        return None;
    }
    if data.len() == 16 {
        let mut block: [u8; 16] = data.try_into().ok()?;
        aes.decrypt(&mut block);
        return Some(block.to_vec());
    }
    // The last two blocks are swapped and the final one may be short.
    let tail = (data.len() - 1) % 16 + 1;
    let head = data.len() - tail - 16;
    let mut out = cbc_decrypt(aes, &[0; 16], &data[..head])?;
    let previous: [u8; 16] = if head == 0 {
        [0; 16]
    } else {
        data[head - 16..head].try_into().ok()?
    };
    let mut swapped: [u8; 16] = data[head..head + 16].try_into().ok()?;
    aes.decrypt(&mut swapped);
    let mut last = [0u8; 16];
    last[..tail].copy_from_slice(&data[head + 16..]);
    last[tail..].copy_from_slice(&swapped[tail..]);
    let mut final_plain = swapped;
    xor(&mut final_plain, &last);
    aes.decrypt(&mut last);
    xor(&mut last, &previous);
    out.extend(last);
    out.extend(&final_plain[..tail]);
    Some(out)
}

fn kerberos_open(key: &[u8], usage: u32, data: &[u8]) -> Option<Vec<u8>> {
    let (cipher, mac) = data.split_at_checked(data.len().checked_sub(12)?)?;
    let constant = |kind: u8| {
        let mut constant = usage.to_be_bytes().to_vec();
        constant.push(kind);
        constant
    };
    let plain = cts_decrypt(&Aes::new(&derive(key, &constant(0xaa))?)?, cipher)?;
    let integrity = hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        &derive(key, &constant(0x55))?,
    );
    let tag = hmac::sign(&integrity, &plain);
    // A decoder for captures: the tag only tells a right key from a wrong one.
    (tag.as_ref()[..12] == *mac).then(|| plain[16.min(plain.len())..].to_vec())
}

/// Decrypts a Kerberos `EncryptedData` cipher with any loaded key, trying the
/// key usages of tickets, replies and authenticators.
pub(crate) fn kerberos_decrypt(cipher: &[u8]) -> Option<Vec<u8>> {
    let secrets = secrets();
    secrets.kerberos.iter().find_map(|key| {
        [2, 3, 8, 9, 11, 1, 7, 12]
            .into_iter()
            .find_map(|usage| kerberos_open(key, usage, cipher))
    })
}

/// Adds an ESP security association: `SPI:CIPHER:HEXKEY[:ICV]` where CIPHER
/// is `aes-gcm` (key followed by the 4-byte salt), `aes-cbc` or `null`.
pub fn add_esp_sa(rule: &str) -> Result<(), String> {
    let usage = || format!("Invalid --esp-sa {rule}: use SPI:aes-gcm|aes-cbc|null:HEXKEY[:ICV]");
    let mut parts = rule.split(':');
    let spi = parts.next().ok_or_else(usage)?;
    let spi = match spi.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => spi.parse(),
    }
    .map_err(|_| usage())?;
    let cipher = parts.next().ok_or_else(usage)?;
    let key = match parts.next() {
        Some(key) if !key.is_empty() => crate::filter::hex(key)?,
        _ => Vec::new(),
    };
    let icv = parts.next().map(|icv| icv.parse::<usize>());
    let (gcm, sizes, default_icv): (bool, &[usize], usize) = match cipher {
        "aes-gcm" => (true, &[20, 36], 16),
        "aes-cbc" => (false, &[16, 24, 32], 12),
        "null" => (false, &[0], 12),
        _ => return Err(usage()),
    };
    if !sizes.contains(&key.len()) {
        return Err(format!("{cipher} key must be {sizes:?} bytes"));
    }
    let icv = match icv {
        Some(Ok(icv)) if icv <= 64 && !gcm => icv,
        None => default_icv,
        _ => return Err(usage()),
    };
    secrets_mut().esp.push(EspSa { spi, gcm, key, icv });
    Ok(())
}

/// Decrypts an ESP packet (`data` starts at the SPI). Returns the next-header
/// number and the inner payload.
pub(crate) fn esp_decrypt(data: &[u8]) -> Option<(u8, Vec<u8>)> {
    let spi = u32::from_be_bytes(data.get(..4)?.try_into().ok()?);
    let secrets = secrets();
    let sa = secrets.esp.iter().find(|sa| sa.spi == spi)?;
    let mut plain = if sa.gcm {
        let (key, salt) = sa.key.split_at(sa.key.len() - 4);
        let algorithm = if key.len() == 16 {
            &aead::AES_128_GCM
        } else {
            &aead::AES_256_GCM
        };
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(algorithm, key).ok()?);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(salt);
        nonce[4..].copy_from_slice(data.get(8..16)?);
        let mut sealed = data.get(16..)?.to_vec();
        let length = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&data[..8]),
                &mut sealed,
            )
            .ok()?
            .len();
        sealed.truncate(length);
        sealed
    } else {
        let body = data.get(8..data.len().checked_sub(sa.icv)?)?;
        if sa.key.is_empty() {
            body.to_vec()
        } else {
            cbc_decrypt(&Aes::new(&sa.key)?, body.get(..16)?, &body[16..])?
        }
    };
    // Trailer: padding 1, 2, 3 …, its length, then the next header.
    let next = plain.pop()?;
    let padding = usize::from(plain.pop()?);
    let payload = plain.len().checked_sub(padding)?;
    let valid = plain[payload..]
        .iter()
        .enumerate()
        .all(|(index, byte)| usize::from(*byte) == index + 1);
    plain.truncate(payload);
    valid.then_some((next, plain))
}

/// Adds a WPA2 passphrase as `PASSPHRASE:SSID`.
pub fn add_wpa_key(rule: &str) -> Result<(), String> {
    let (passphrase, ssid) = rule
        .rsplit_once(':')
        .filter(|(passphrase, ssid)| (8..=63).contains(&passphrase.len()) && !ssid.is_empty())
        .ok_or("Invalid --wpa-key: use PASSPHRASE:SSID with an 8–63 character passphrase")?;
    let mut pmk = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA1,
        NonZeroU32::new(4096).unwrap_or(NonZeroU32::MIN),
        ssid.as_bytes(),
        passphrase.as_bytes(),
        &mut pmk,
    );
    secrets_mut().wpa.push(pmk);
    Ok(())
}

/// The CCMP temporal key of a 4-way handshake, for the first configured
/// passphrase whose key confirms the MIC of handshake message 2.
/// `eapol` is that message from its version byte on.
pub(crate) fn wpa_temporal_key(
    ap: &[u8; 6],
    station: &[u8; 6],
    anonce: &[u8; 32],
    eapol: &[u8],
) -> Option<[u8; 16]> {
    let snonce = eapol.get(17..49)?;
    let mic = eapol.get(81..97)?;
    let mut data = b"Pairwise key expansion\0".to_vec();
    data.extend(ap.min(station));
    data.extend(ap.max(station));
    data.extend(anonce.as_slice().min(snonce));
    data.extend(anonce.as_slice().max(snonce));
    data.push(0);
    let mut zeroed = eapol.to_vec();
    zeroed[81..97].fill(0);
    secrets().wpa.iter().find_map(|pmk| {
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, pmk);
        // PRF-384: three HMAC-SHA1 outputs with a trailing counter.
        let mut ptk = Vec::new();
        for counter in 0..3u8 {
            *data.last_mut()? = counter;
            ptk.extend(hmac::sign(&key, &data).as_ref());
        }
        let confirmation = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &ptk[..16]);
        (hmac::sign(&confirmation, &zeroed).as_ref()[..16] == *mic)
            .then(|| ptk[32..48].try_into().ok())
            .flatten()
    })
}

/// AES-CCM with an 8-byte MIC and 2-byte length field, as CCMP uses it.
pub(crate) fn ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 13],
    aad: &[u8],
    data: &[u8],
) -> Option<Vec<u8>> {
    let aes = Aes::new(key)?;
    let (cipher, mic) = data.split_at_checked(data.len().checked_sub(8)?)?;
    let counter = |index: u16| {
        let mut block = [0u8; 16];
        block[0] = 1;
        block[1..14].copy_from_slice(nonce);
        block[14..].copy_from_slice(&index.to_be_bytes());
        aes.encrypt(&mut block);
        block
    };
    let mut plain = cipher.to_vec();
    for (index, chunk) in plain.chunks_mut(16).enumerate() {
        xor(chunk, &counter(u16::try_from(index + 1).ok()?));
    }
    // CBC-MAC over B0, the length-prefixed AAD and the plaintext.
    let mut mac = [0u8; 16];
    mac[0] = 0x59;
    mac[1..14].copy_from_slice(nonce);
    mac[14..].copy_from_slice(&u16::try_from(plain.len()).ok()?.to_be_bytes());
    aes.encrypt(&mut mac);
    let mut header = u16::try_from(aad.len()).ok()?.to_be_bytes().to_vec();
    header.extend(aad);
    for chunk in header.chunks(16).chain(plain.chunks(16)) {
        xor(&mut mac, chunk);
        aes.encrypt(&mut mac);
    }
    xor(&mut mac, &counter(0));
    (mac[..8] == *mic).then_some(plain)
}

/// Decrypts the body of a protected 802.11 data frame (CCMP header included)
/// with temporal key `key`; `header` is the 802.11 MAC header.
pub(crate) fn ccmp_decrypt(
    key: &[u8; 16],
    header: &[u8],
    qos: bool,
    body: &[u8],
) -> Option<Vec<u8>> {
    let ccmp = body.get(..8)?;
    if ccmp[3] & 0x20 == 0 || header.len() < 24 {
        return None; // Not CCMP (no extended IV).
    }
    let priority = if qos {
        header[header.len() - 2] & 0x0f
    } else {
        0
    };
    let mut nonce = [0u8; 13];
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(&header[10..16]);
    nonce[7..].copy_from_slice(&[ccmp[7], ccmp[6], ccmp[5], ccmp[4], ccmp[1], ccmp[0]]);
    let mut aad = vec![header[0] & 0x8f, (header[1] & 0xc7) | 0x40];
    aad.extend(&header[4..22]);
    aad.extend([header[22] & 0x0f, 0]);
    if header[1] & 3 == 3 {
        aad.extend(header.get(24..30)?);
    }
    if qos {
        aad.extend([priority, 0]);
    }
    ccm_decrypt(key, &nonce, &aad, &body[8..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        crate::filter::hex(text).unwrap()
    }

    #[test]
    fn kerberos_primitives_match_the_rfc_vectors() {
        // RFC 3961 A.1.
        assert_eq!(nfold(b"012345", 8), hex("be072631276b1955"));
        assert_eq!(
            nfold(b"password", 21),
            hex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e")
        );
        // RFC 3962 B: CBC with ciphertext stealing, 17 and 32 bytes.
        let aes = Aes::new(b"chicken teriyaki").unwrap();
        assert_eq!(
            cts_decrypt(&aes, &hex("c6353568f2bf8cb4d8a580362da7ff7f97")).unwrap(),
            b"I would like the "
        );
        assert_eq!(
            cts_decrypt(
                &aes,
                &hex("39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584")
            )
            .unwrap(),
            b"I would like the General Gau's C"
        );
        assert!(cts_decrypt(&aes, &[0; 15]).is_none());
    }

    #[test]
    fn rejects_malformed_keys_and_keytabs() {
        for bad in [
            "",
            "1:aes-gcm:00",
            "x:null:",
            "1:rc4:00",
            "1:aes-cbc:zz",
            "1:null::99",
        ] {
            assert!(add_esp_sa(bad).is_err(), "{bad}");
        }
        assert!(add_wpa_key("short:net").is_err());
        assert!(add_wpa_key("no-ssid-here").is_err());
        assert!(load_keytab(b"\x05\x01").is_err());
        assert!(load_keytab(b"\x05\x02\x00\x00\x00\x09ab").is_err());
        assert_eq!(load_keytab(b"\x05\x02"), Ok(0));
        assert!(esp_decrypt(&[0; 3]).is_none());
        assert!(ccm_decrypt(&[0; 16], &[0; 13], &[], &[0; 7]).is_none());
    }
}
