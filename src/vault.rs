//! Verschlüsselung aller Geheimnisse.
//!
//! Aufbau: Aus dem Master-Passwort wird per Argon2id ein Schlüssel (KEK) abgeleitet.
//! Der KEK verschlüsselt einen zufälligen Datenschlüssel (DEK), der wiederum die
//! Geheimnisse (XChaCha20-Poly1305) verschlüsselt. Ein Passwortwechsel muss dadurch
//! nur den DEK neu verpacken.

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const WRAP_AAD: &str = "sshelf/dek/v1";

/// Argon2id-Parameter; werden mitgespeichert, damit sie später erhöht werden können.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self { m_kib: 64 * 1024, t: 3, p: 1 }
    }
}

/// Was in der Datenbank liegt, um den Tresor zu öffnen.
#[derive(Clone, Debug)]
pub struct WrappedDek {
    pub salt: Vec<u8>,
    pub params: KdfParams,
    pub wrapped: Vec<u8>,
}

/// Der entsperrte Datenschlüssel. Wird beim Verwerfen aus dem Speicher gelöscht.
pub struct Dek(Zeroizing<[u8; KEY_LEN]>);

fn derive_kek(password: &str, salt: &[u8], p: KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(KEY_LEN)).map_err(|e| anyhow!("Argon2: {e}"))?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow!("Argon2: {e}"))?;
    Ok(out)
}

fn seal_with(key: &[u8; KEY_LEN], aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("Schlüssellänge"))?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("Zufallsquelle: {e}"))?;
    let ct = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .map_err(|_| anyhow!("Verschlüsselung fehlgeschlagen"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open_with(key: &[u8; KEY_LEN], aad: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_LEN {
        bail!("Geheimnis ist beschädigt");
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().context("Nonce")?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| anyhow!("Schlüssellänge"))?;
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: aad.as_bytes() })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("Entschlüsselung fehlgeschlagen"))
}

impl Dek {
    /// Erzeugt einen neuen Tresor für ein Master-Passwort.
    pub fn create(password: &str) -> Result<(Dek, WrappedDek)> {
        let mut dek = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(dek.as_mut()).map_err(|e| anyhow!("Zufallsquelle: {e}"))?;
        let dek = Dek(dek);
        let wrapped = dek.wrap(password)?;
        Ok((dek, wrapped))
    }

    /// Verpackt den DEK für ein (neues) Passwort.
    pub fn wrap(&self, password: &str) -> Result<WrappedDek> {
        let mut salt = vec![0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|e| anyhow!("Zufallsquelle: {e}"))?;
        let params = KdfParams::default();
        let kek = derive_kek(password, &salt, params)?;
        let wrapped = seal_with(&kek, WRAP_AAD, self.0.as_ref())?;
        Ok(WrappedDek { salt, params, wrapped })
    }

    /// Öffnet den Tresor. `None` bedeutet: falsches Passwort.
    pub fn unlock(password: &str, w: &WrappedDek) -> Result<Option<Dek>> {
        let kek = derive_kek(password, &w.salt, w.params)?;
        let Ok(raw) = open_with(&kek, WRAP_AAD, &w.wrapped) else {
            return Ok(None);
        };
        let bytes: [u8; KEY_LEN] =
            raw.as_slice().try_into().map_err(|_| anyhow!("Tresor ist beschädigt"))?;
        Ok(Some(Dek(Zeroizing::new(bytes))))
    }

    /// `aad` bindet den Geheimtext an seinen Zweck, damit Werte nicht vertauscht werden können.
    pub fn seal(&self, aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        seal_with(&self.0, aad, plaintext)
    }

    pub fn open_string(&self, aad: &str, data: &[u8]) -> Result<Zeroizing<String>> {
        let raw = open_with(&self.0, aad, data)?;
        let s = std::str::from_utf8(&raw).context("Geheimnis ist kein Text")?;
        Ok(Zeroizing::new(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let (dek, wrapped) = Dek::create("korrekt").unwrap();
        let ct = dek.seal("a", b"geheim").unwrap();
        assert!(!ct.windows(6).any(|w| w == b"geheim"));
        assert!(Dek::unlock("falsch", &wrapped).unwrap().is_none());
        let again = Dek::unlock("korrekt", &wrapped).unwrap().unwrap();
        assert_eq!(again.open_string("a", &ct).unwrap().as_str(), "geheim");
    }

    #[test]
    fn aad_and_tampering_are_detected() {
        let (dek, _) = Dek::create("x").unwrap();
        let mut ct = dek.seal("a", b"geheim").unwrap();
        assert!(dek.open_string("b", &ct).is_err());
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(dek.open_string("a", &ct).is_err());
    }

    #[test]
    fn rewrap_keeps_data_readable() {
        let (dek, _) = Dek::create("alt").unwrap();
        let ct = dek.seal("a", b"x").unwrap();
        let neu = dek.wrap("neu").unwrap();
        let d2 = Dek::unlock("neu", &neu).unwrap().unwrap();
        assert_eq!(d2.open_string("a", &ct).unwrap().as_str(), "x");
    }
}
