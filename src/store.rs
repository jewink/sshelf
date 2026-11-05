//! SQLite-Datenbank: Verbindungen, Schlüssel, bekannte Hosts, Einstellungen.
//! Geheimnisse liegen nur verschlüsselt darin (siehe `vault`).

use crate::vault::{Dek, KdfParams, WrappedDek};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const AAD_PRIVATE: &str = "sshelf/key/private";
const AAD_PASSPHRASE: &str = "sshelf/key/passphrase";
const AAD_PASSWORD: &str = "sshelf/conn/password";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    Key,
    Password,
    Agent,
    Interactive,
}

impl AuthKind {
    pub const ALL: [AuthKind; 4] =
        [AuthKind::Key, AuthKind::Password, AuthKind::Agent, AuthKind::Interactive];

    fn as_str(self) -> &'static str {
        match self {
            AuthKind::Key => "key",
            AuthKind::Password => "password",
            AuthKind::Agent => "agent",
            AuthKind::Interactive => "interactive",
        }
    }

    fn parse(s: &str) -> AuthKind {
        match s {
            "password" => AuthKind::Password,
            "agent" => AuthKind::Agent,
            "interactive" => AuthKind::Interactive,
            _ => AuthKind::Key,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            AuthKind::Key => "Schlüssel",
            AuthKind::Password => "Passwort",
            AuthKind::Agent => "SSH-Agent",
            AuthKind::Interactive => "Nachfragen",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionRec {
    pub id: Option<i64>,
    pub name: String,
    pub group: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthKind,
    pub key_id: Option<i64>,
    pub jump_id: Option<i64>,
    pub keepalive_secs: u32,
    pub startup_cmd: String,
    pub notes: String,
    pub has_password: bool,
    pub last_used: Option<i64>,
}

impl Default for ConnectionRec {
    fn default() -> Self {
        Self {
            id: None,
            name: String::new(),
            group: String::new(),
            host: String::new(),
            port: 22,
            username: std::env::var("USER").unwrap_or_default(),
            auth: AuthKind::Key,
            key_id: None,
            jump_id: None,
            keepalive_secs: 30,
            startup_cmd: String::new(),
            notes: String::new(),
            has_password: false,
            last_used: None,
        }
    }
}

/// Was beim Speichern mit dem hinterlegten Passwort passieren soll.
pub enum PasswordChange {
    Keep,
    Set(Zeroizing<String>),
    Clear,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyRec {
    pub id: i64,
    pub name: String,
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub has_passphrase: bool,
    pub encrypted: bool,
}

/// Neuer Schlüssel für [`Store::insert_key`].
pub struct NewKey {
    pub name: String,
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub private_pem: Zeroizing<String>,
    /// Ist die PEM-Datei selbst passphrasengeschützt?
    pub encrypted: bool,
    pub passphrase: Option<Zeroizing<String>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KnownHost {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
}

#[derive(Debug, PartialEq)]
pub enum HostKeyStatus {
    Trusted,
    Unknown,
    Changed { old_fingerprint: String },
}

pub struct Store {
    conn: Connection,
    path: PathBuf,
}

fn restrict_permissions(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
            std::fs::create_dir_all(dir).with_context(|| format!("Ordner {} anlegen", dir.display()))?;
            restrict_permissions(dir, 0o700);
        }
        let conn = Connection::open(path)
            .with_context(|| format!("Datenbank {} öffnen", path.display()))?;
        let mut store = Store { conn, path: path.to_owned() };
        store.prepare()?;
        // Erst jetzt: Eine fremde Datei darf nicht verändert werden.
        restrict_permissions(path, 0o600);
        Ok(store)
    }

    /// Platzhalter, solange die eigentliche Datenbank nicht geöffnet werden konnte.
    pub fn open_memory() -> Result<Store> {
        let mut store = Store { conn: Connection::open_in_memory()?, path: PathBuf::from(":memory:") };
        store.prepare()?;
        Ok(store)
    }

    fn prepare(&mut self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;")
            .and_then(|()| self.conn.busy_timeout(std::time::Duration::from_secs(3)))
            .context("Das ist keine gültige SSHelf-Datenbank")?;
        self.migrate()
    }

    /// Schreibt eine Kopie der Datenbank in eine neue Datei.
    pub fn copy_to(&self, target: &Path) -> Result<()> {
        if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
            std::fs::create_dir_all(dir).with_context(|| format!("Ordner {} anlegen", dir.display()))?;
            restrict_permissions(dir, 0o700);
        }
        let name = target.to_str().context("Der Pfad enthält ungültige Zeichen")?;
        self.conn
            .execute("VACUUM INTO ?1", [name])
            .with_context(|| format!("Kopie nach {} anlegen", target.display()))?;
        restrict_permissions(target, 0o600);
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&mut self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .context("Das ist keine gültige SSHelf-Datenbank")?;
        let tables: i64 = self
            .conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .context("Das ist keine gültige SSHelf-Datenbank")?;
        if version == 0 && tables > 0 {
            bail!("Diese Datei gehört zu einem anderen Programm und wurde nicht verändert.");
        }
        if version > 1 {
            bail!("Die Datenbank stammt von einer neueren Programmversion");
        }
        if version == 0 {
            self.conn.execute_batch(
                "BEGIN;
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
                 CREATE TABLE keys (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    private_enc BLOB NOT NULL,
                    encrypted INTEGER NOT NULL,
                    passphrase_enc BLOB
                 );
                 CREATE TABLE connections (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    grp TEXT NOT NULL DEFAULT '',
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    auth TEXT NOT NULL,
                    key_id INTEGER REFERENCES keys(id) ON DELETE SET NULL,
                    jump_id INTEGER REFERENCES connections(id) ON DELETE SET NULL,
                    keepalive_secs INTEGER NOT NULL DEFAULT 30,
                    startup_cmd TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    password_enc BLOB,
                    last_used INTEGER
                 );
                 CREATE TABLE known_hosts (
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    algorithm TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    PRIMARY KEY (host, port)
                 );
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        }
        Ok(())
    }

    // --- Einstellungen und Tresor -------------------------------------------------------

    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.conn
            .query_row("SELECT value FROM meta WHERE key=?1", [format!("cfg.{key}")], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)",
            params![format!("cfg.{key}"), value.as_bytes()],
        )?;
        Ok(())
    }

    fn meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn load_vault(&self) -> Result<Option<WrappedDek>> {
        let (Some(salt), Some(wrapped), Some(p)) =
            (self.meta("vault.salt")?, self.meta("vault.wrapped")?, self.meta("vault.kdf")?)
        else {
            return Ok(None);
        };
        let p = String::from_utf8(p)?;
        let nums: Vec<u32> = p.split(',').filter_map(|s| s.parse().ok()).collect();
        let [m_kib, t, p] = nums[..] else { bail!("Tresor-Parameter sind beschädigt") };
        Ok(Some(WrappedDek { salt, wrapped, params: KdfParams { m_kib, t, p } }))
    }

    pub fn save_vault(&mut self, w: &WrappedDek) -> Result<()> {
        let tx = self.conn.transaction()?;
        let kdf = format!("{},{},{}", w.params.m_kib, w.params.t, w.params.p);
        for (k, v) in [
            ("vault.salt", w.salt.as_slice()),
            ("vault.wrapped", w.wrapped.as_slice()),
            ("vault.kdf", kdf.as_bytes()),
        ] {
            tx.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", params![k, v])?;
        }
        tx.commit()?;
        Ok(())
    }

    // --- Verbindungen --------------------------------------------------------------------

    pub fn connections(&self) -> Result<Vec<ConnectionRec>> {
        let mut st = self.conn.prepare(
            "SELECT id,name,grp,host,port,username,auth,key_id,jump_id,keepalive_secs,startup_cmd,
                    notes,password_enc IS NOT NULL,last_used
             FROM connections ORDER BY grp COLLATE NOCASE, name COLLATE NOCASE",
        )?;
        let rows = st.query_map([], |r| {
            Ok(ConnectionRec {
                id: Some(r.get(0)?),
                name: r.get(1)?,
                group: r.get(2)?,
                host: r.get(3)?,
                port: r.get(4)?,
                username: r.get(5)?,
                auth: AuthKind::parse(&r.get::<_, String>(6)?),
                key_id: r.get(7)?,
                jump_id: r.get(8)?,
                keepalive_secs: r.get(9)?,
                startup_cmd: r.get(10)?,
                notes: r.get(11)?,
                has_password: r.get(12)?,
                last_used: r.get(13)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Legt die Verbindung an oder aktualisiert sie und liefert ihre ID.
    pub fn save_connection(
        &self,
        c: &ConnectionRec,
        pw: PasswordChange,
        dek: &Dek,
    ) -> Result<i64> {
        let id = match c.id {
            Some(id) => {
                self.conn.execute(
                    "UPDATE connections SET name=?2,grp=?3,host=?4,port=?5,username=?6,auth=?7,
                     key_id=?8,jump_id=?9,keepalive_secs=?10,startup_cmd=?11,notes=?12 WHERE id=?1",
                    params![
                        id, c.name, c.group, c.host, c.port, c.username, c.auth.as_str(),
                        c.key_id, c.jump_id, c.keepalive_secs, c.startup_cmd, c.notes
                    ],
                )?;
                id
            }
            None => {
                self.conn.execute(
                    "INSERT INTO connections(name,grp,host,port,username,auth,key_id,jump_id,
                     keepalive_secs,startup_cmd,notes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![
                        c.name, c.group, c.host, c.port, c.username, c.auth.as_str(),
                        c.key_id, c.jump_id, c.keepalive_secs, c.startup_cmd, c.notes
                    ],
                )?;
                self.conn.last_insert_rowid()
            }
        };
        match pw {
            PasswordChange::Keep => {}
            PasswordChange::Clear => {
                self.conn.execute("UPDATE connections SET password_enc=NULL WHERE id=?1", [id])?;
            }
            PasswordChange::Set(p) => {
                let enc = dek.seal(AAD_PASSWORD, p.as_bytes())?;
                self.conn
                    .execute("UPDATE connections SET password_enc=?2 WHERE id=?1", params![id, enc])?;
            }
        }
        Ok(id)
    }

    pub fn delete_connection(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM connections WHERE id=?1", [id])?;
        Ok(())
    }

    /// Kopiert auch das gespeicherte Passwort (der Name wird mit „(Kopie)“ ergänzt).
    pub fn duplicate_connection(&self, id: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO connections(name,grp,host,port,username,auth,key_id,jump_id,keepalive_secs,
                                     startup_cmd,notes,password_enc)
             SELECT name||' (Kopie)',grp,host,port,username,auth,key_id,jump_id,keepalive_secs,
                    startup_cmd,notes,password_enc FROM connections WHERE id=?1",
            [id],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn touch_connection(&self, id: i64) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn.execute("UPDATE connections SET last_used=?2 WHERE id=?1", params![id, now])?;
        Ok(())
    }

    pub fn connection_password(&self, id: i64, dek: &Dek) -> Result<Option<Zeroizing<String>>> {
        let enc: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT password_enc FROM connections WHERE id=?1", [id], |r| r.get(0))?;
        enc.map(|e| dek.open_string(AAD_PASSWORD, &e)).transpose()
    }

    // --- Schlüssel -----------------------------------------------------------------------

    pub fn keys(&self) -> Result<Vec<KeyRec>> {
        let mut st = self.conn.prepare(
            "SELECT id,name,algorithm,public_key,fingerprint,passphrase_enc IS NOT NULL,encrypted
             FROM keys ORDER BY name COLLATE NOCASE",
        )?;
        let rows = st.query_map([], |r| {
            Ok(KeyRec {
                id: r.get(0)?,
                name: r.get(1)?,
                algorithm: r.get(2)?,
                public_key: r.get(3)?,
                fingerprint: r.get(4)?,
                has_passphrase: r.get(5)?,
                encrypted: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn insert_key(&self, k: &NewKey, dek: &Dek) -> Result<i64> {
        let private_enc = dek.seal(AAD_PRIVATE, k.private_pem.as_bytes())?;
        let pass_enc =
            k.passphrase.as_ref().map(|p| dek.seal(AAD_PASSPHRASE, p.as_bytes())).transpose()?;
        self.conn.execute(
            "INSERT INTO keys(name,algorithm,public_key,fingerprint,private_enc,encrypted,passphrase_enc)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![k.name, k.algorithm, k.public_key, k.fingerprint, private_enc, k.encrypted, pass_enc],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn rename_key(&self, id: i64, name: &str) -> Result<()> {
        self.conn.execute("UPDATE keys SET name=?2 WHERE id=?1", params![id, name])?;
        Ok(())
    }

    pub fn delete_key(&self, id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM keys WHERE id=?1", [id])?;
        Ok(())
    }

    /// Privater Schlüssel (PEM) und ggf. seine gespeicherte Passphrase.
    pub fn key_secret(
        &self,
        id: i64,
        dek: &Dek,
    ) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>)> {
        let (p, s): (Vec<u8>, Option<Vec<u8>>) = self.conn.query_row(
            "SELECT private_enc,passphrase_enc FROM keys WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let pem = dek.open_string(AAD_PRIVATE, &p)?;
        let pass = s.map(|e| dek.open_string(AAD_PASSPHRASE, &e)).transpose()?;
        Ok((pem, pass))
    }

    // --- Bekannte Hosts ------------------------------------------------------------------

    pub fn check_host_key(&self, host: &str, port: u16, public_key: &str) -> Result<HostKeyStatus> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT public_key,fingerprint FROM known_hosts WHERE host=?1 AND port=?2",
                params![host, port],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(match row {
            None => HostKeyStatus::Unknown,
            Some((k, _)) if k == public_key => HostKeyStatus::Trusted,
            Some((_, old_fingerprint)) => HostKeyStatus::Changed { old_fingerprint },
        })
    }

    pub fn trust_host_key(
        &self,
        host: &str,
        port: u16,
        algorithm: &str,
        public_key: &str,
        fingerprint: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO known_hosts(host,port,algorithm,public_key,fingerprint)
             VALUES(?1,?2,?3,?4,?5)",
            params![host, port, algorithm, public_key, fingerprint],
        )?;
        Ok(())
    }

    pub fn known_hosts(&self) -> Result<Vec<KnownHost>> {
        let mut st = self.conn.prepare(
            "SELECT host,port,algorithm,fingerprint FROM known_hosts ORDER BY host COLLATE NOCASE,port",
        )?;
        let rows = st.query_map([], |r| {
            Ok(KnownHost {
                host: r.get(0)?,
                port: r.get(1)?,
                algorithm: r.get(2)?,
                fingerprint: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn forget_host(&self, host: &str, port: u16) -> Result<()> {
        self.conn
            .execute("DELETE FROM known_hosts WHERE host=?1 AND port=?2", params![host, port])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempdir::Dir, Store) {
        let d = tempdir::Dir::new();
        let s = Store::open(&d.0.join("t.db")).unwrap();
        (d, s)
    }

    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let mut b = [0u8; 8];
                getrandom::fill(&mut b).unwrap();
                let p = std::env::temp_dir().join(format!("sshelf-test-{:x}", u64::from_le_bytes(b)));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn new_key(name: &str, pem: &str) -> NewKey {
        NewKey {
            name: name.into(),
            algorithm: "ssh-ed25519".into(),
            public_key: "ssh-ed25519 AAAA".into(),
            fingerprint: "SHA256:x".into(),
            private_pem: Zeroizing::new(pem.into()),
            encrypted: false,
            passphrase: None,
        }
    }

    #[test]
    fn secrets_are_not_stored_in_plaintext_and_survive_reopen() {
        let (d, s) = temp_db();
        let (dek, w) = Dek::create("pw").unwrap();
        let mut s = s;
        s.save_vault(&w).unwrap();
        let kid = s.insert_key(&new_key("k", "TOPSECRETPEM"), &dek).unwrap();
        let c = ConnectionRec { name: "a".into(), host: "h".into(), key_id: Some(kid), ..Default::default() };
        let cid = s
            .save_connection(&c, PasswordChange::Set(Zeroizing::new("TOPSECRETPW".into())), &dek)
            .unwrap();
        let path = s.path().to_owned();
        drop(s);

        let raw = std::fs::read(&path).unwrap();
        for needle in [&b"TOPSECRETPEM"[..], &b"TOPSECRETPW"[..]] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle), "Klartext in der DB");
        }

        let s = Store::open(&d.0.join("t.db")).unwrap();
        let w = s.load_vault().unwrap().unwrap();
        let dek = Dek::unlock("pw", &w).unwrap().unwrap();
        assert_eq!(s.key_secret(kid, &dek).unwrap().0.as_str(), "TOPSECRETPEM");
        assert_eq!(s.connection_password(cid, &dek).unwrap().unwrap().as_str(), "TOPSECRETPW");
        assert!(s.connections().unwrap()[0].has_password);
    }

    #[test]
    fn deleting_a_key_detaches_it_from_connections() {
        let (_d, s) = temp_db();
        let (dek, _) = Dek::create("pw").unwrap();
        let kid = s.insert_key(&new_key("k", "x"), &dek).unwrap();
        let c = ConnectionRec { name: "a".into(), host: "h".into(), key_id: Some(kid), ..Default::default() };
        s.save_connection(&c, PasswordChange::Keep, &dek).unwrap();
        s.delete_key(kid).unwrap();
        assert_eq!(s.connections().unwrap()[0].key_id, None);
    }

    #[test]
    fn foreign_files_are_rejected_and_left_untouched() {
        let d = tempdir::Dir::new();
        let text = d.0.join("text.db");
        std::fs::write(&text, "das ist keine datenbank, sondern ein etwas längerer text").unwrap();
        let before = std::fs::read(&text).unwrap();
        assert!(Store::open(&text).is_err());
        assert_eq!(std::fs::read(&text).unwrap(), before);

        let other = d.0.join("anderes.db");
        Connection::open(&other).unwrap().execute_batch("CREATE TABLE fremd(x)").unwrap();
        let before = std::fs::read(&other).unwrap();
        let err = Store::open(&other).err().unwrap().to_string();
        assert!(err.contains("anderen Programm"), "{err}");
        assert_eq!(std::fs::read(&other).unwrap(), before);
    }

    #[test]
    fn copy_keeps_all_data_and_refuses_to_overwrite() {
        let (d, mut s) = temp_db();
        let (dek, w) = Dek::create("pw").unwrap();
        s.save_vault(&w).unwrap();
        s.insert_key(&new_key("k", "pem"), &dek).unwrap();
        let target = d.0.join("neu/unter/kopie.db");
        s.copy_to(&target).unwrap();
        let copy = Store::open(&target).unwrap();
        assert_eq!(copy.keys().unwrap().len(), 1);
        let w2 = copy.load_vault().unwrap().unwrap();
        let dek2 = Dek::unlock("pw", &w2).unwrap().unwrap();
        let id = copy.keys().unwrap()[0].id;
        assert_eq!(copy.key_secret(id, &dek2).unwrap().0.as_str(), "pem");
        assert!(s.copy_to(&target).is_err(), "Vorhandene Dateien werden nicht überschrieben");
    }

    #[test]
    fn host_key_states() {
        let (_d, s) = temp_db();
        assert_eq!(s.check_host_key("h", 22, "K1").unwrap(), HostKeyStatus::Unknown);
        s.trust_host_key("h", 22, "ed", "K1", "F1").unwrap();
        assert_eq!(s.check_host_key("h", 22, "K1").unwrap(), HostKeyStatus::Trusted);
        assert_eq!(
            s.check_host_key("h", 22, "K2").unwrap(),
            HostKeyStatus::Changed { old_fingerprint: "F1".into() }
        );
        assert_eq!(s.check_host_key("h", 2222, "K1").unwrap(), HostKeyStatus::Unknown);
    }
}
