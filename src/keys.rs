//! Prüfen, Importieren und Erzeugen von SSH-Schlüsseln.

use crate::store::NewKey;
use anyhow::{Context, Result, anyhow, bail};
use russh::keys::{self, Algorithm, HashAlg, PrivateKey};
use zeroize::Zeroizing;

/// Ist der Schlüsseltext selbst passphrasengeschützt?
pub fn is_encrypted(pem: &str) -> bool {
    matches!(keys::decode_secret_key(pem, None), Err(keys::Error::KeyIsEncrypted))
}

fn describe(name: &str, key: &PrivateKey, pem: Zeroizing<String>, encrypted: bool, passphrase: Option<Zeroizing<String>>) -> Result<NewKey> {
    let mut public = key.public_key().clone();
    public.set_comment(name);
    Ok(NewKey {
        name: name.to_owned(),
        algorithm: key.algorithm().to_string(),
        public_key: public.to_openssh().context("Öffentlichen Schlüssel erzeugen")?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        private_pem: pem,
        encrypted,
        passphrase,
    })
}

/// Prüft einen eingefügten oder geladenen privaten Schlüssel und bereitet ihn zum Speichern vor.
pub fn prepare_import(name: &str, pem: &str, passphrase: &str, save_passphrase: bool) -> Result<NewKey> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Bitte einen Namen für den Schlüssel eingeben.");
    }
    let pem = Zeroizing::new(format!("{}\n", pem.replace("\r\n", "\n").trim()));
    if pem.trim().is_empty() {
        bail!("Bitte den privaten Schlüssel einfügen oder eine Datei laden.");
    }
    if pem.contains("PUBLIC KEY") || pem.trim_start().starts_with("ssh-") {
        bail!("Das ist ein öffentlicher Schlüssel. Benötigt wird der private Schlüssel.");
    }
    let encrypted = is_encrypted(&pem);
    if encrypted && passphrase.is_empty() {
        bail!("Dieser Schlüssel ist geschützt. Bitte die Passphrase eingeben.");
    }
    let key = keys::decode_secret_key(&pem, encrypted.then_some(passphrase)).map_err(|e| {
        if encrypted {
            anyhow!("Die Passphrase ist falsch.")
        } else {
            anyhow!("Der Schlüssel kann nicht gelesen werden: {e}")
        }
    })?;
    let stored = (encrypted && save_passphrase).then(|| Zeroizing::new(passphrase.to_owned()));
    describe(name, &key, pem, encrypted, stored)
}

/// Erzeugt einen neuen Ed25519-Schlüssel.
pub fn generate(name: &str) -> Result<NewKey> {
    let name = name.trim();
    if name.is_empty() {
        bail!("Bitte einen Namen für den Schlüssel eingeben.");
    }
    let mut key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|e| anyhow!("Schlüssel erzeugen: {e}"))?;
    key.set_comment(name);
    let pem = key
        .to_openssh(keys::ssh_key::LineEnding::LF)
        .map_err(|e| anyhow!("Schlüssel kodieren: {e}"))?;
    describe(name, &key, Zeroizing::new(pem.as_str().to_owned()), false, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // NewKey hat bewusst kein Debug, damit Geheimnisse nie in Logs oder Panics landen.
    fn err(r: Result<NewKey>) -> String {
        match r {
            Ok(_) => panic!("Fehler erwartet"),
            Err(e) => e.to_string(),
        }
    }

    /// Erzeugt mit dem echten ssh-keygen einen Schlüssel, damit das Format realistisch ist.
    fn keygen(kind: &str, pass: &str, extra: &[&str]) -> String {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        let dir = std::env::temp_dir().join(format!("sshelf-key-{:x}", u64::from_le_bytes(b)));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("k");
        let ok = Command::new("ssh-keygen")
            .args(["-q", "-t", kind, "-N", pass, "-f"])
            .arg(&f)
            .args(extra)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let pem = std::fs::read_to_string(&f).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        pem
    }

    #[test]
    fn imports_plain_keys_of_all_common_types() {
        for (kind, extra) in [("ed25519", &[][..]), ("ecdsa", &[][..]), ("rsa", &["-b", "2048"][..])] {
            let k = prepare_import("k", &keygen(kind, "", extra), "", true).unwrap();
            assert!(!k.encrypted, "{kind}");
            assert!(k.fingerprint.starts_with("SHA256:"), "{kind}");
            assert!(k.public_key.ends_with(" k"), "{kind}: {}", k.public_key);
        }
    }

    #[test]
    fn imports_legacy_pem_rsa() {
        let k = prepare_import("k", &keygen("rsa", "", &["-b", "2048", "-m", "PEM"]), "", true).unwrap();
        assert!(k.algorithm.contains("rsa"));
    }

    #[test]
    fn encrypted_key_needs_correct_passphrase() {
        let pem = keygen("ed25519", "geheim", &[]);
        assert!(is_encrypted(&pem));
        assert!(err(prepare_import("k", &pem, "", true)).contains("Passphrase"));
        assert!(err(prepare_import("k", &pem, "falsch", true)).contains("falsch"));
        let saved = prepare_import("k", &pem, "geheim", true).unwrap();
        assert_eq!(saved.passphrase.unwrap().as_str(), "geheim");
        assert!(prepare_import("k", &pem, "geheim", false).unwrap().passphrase.is_none());
    }

    #[test]
    fn rejects_garbage_and_public_keys() {
        assert!(prepare_import("k", "kein schlüssel", "", true).is_err());
        assert!(err(prepare_import("k", "ssh-ed25519 AAAA x", "", true)).contains("öffentlicher"));
        assert!(prepare_import("", "x", "", true).is_err());
    }

    #[test]
    fn generated_key_can_be_read_back() {
        let k = generate("neu").unwrap();
        assert!(k.public_key.starts_with("ssh-ed25519 "));
        let again = prepare_import("neu", &k.private_pem, "", true).unwrap();
        assert_eq!(again.fingerprint, k.fingerprint);
    }
}
