//! Der SSH-Teil: baut die Verbindung (ggf. über Jump-Hosts) auf, authentifiziert sich und
//! koppelt den Kanal an das Terminal. Läuft asynchron, Rückfragen gehen über `Prompt` an die UI.

use crate::store::{HostKeyStatus, Store};
use crate::term::{Prompt, PromptField, Shared, Status};
use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;
use russh::client::{self, KeyboardInteractiveAuthResponse as KiResp};
use russh::keys::agent::client::AgentClient;
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, MethodKind, MethodSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

const TCP_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_ATTEMPTS: usize = 3;

pub enum HopAuth {
    Key { name: String, pem: Zeroizing<String>, passphrase: Option<Zeroizing<String>> },
    Password(Option<Zeroizing<String>>),
    /// Pfad des Agent-Sockets (`SSH_AUTH_SOCK`), falls gesetzt.
    Agent(Option<std::path::PathBuf>),
    Interactive,
}

/// Eine Station der Verbindung. Die letzte ist das Ziel, alle davor sind Jump-Hosts.
pub struct Hop {
    pub label: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: HopAuth,
    pub keepalive_secs: u32,
}

pub struct Plan {
    pub hops: Vec<Hop>,
    pub startup_cmd: String,
}

pub enum Cmd {
    Input(Vec<u8>),
    Resize { cols: u16, rows: u16, px_w: u16, px_h: u16 },
    Close,
}

/// Prüft den Hostschlüssel gegen die Datenbank und fragt bei unbekannten Hosts nach.
struct HostCheck {
    host: String,
    port: u16,
    store: Arc<Mutex<Store>>,
    shared: Arc<Shared>,
    rejection: Arc<Mutex<Option<String>>>,
}

impl client::Handler for HostCheck {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let public = key.public_key();
        let algorithm = public.algorithm().to_string();
        let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
        let openssh = public.to_openssh().map_err(|_| russh::Error::KexInit)?;
        // Kommentar abschneiden: verglichen wird nur "Algorithmus Schlüsselmaterial".
        let openssh = openssh.split_whitespace().take(2).collect::<Vec<_>>().join(" ");

        let status = self.store.lock().check_host_key(&self.host, self.port, &openssh);
        match status {
            Ok(HostKeyStatus::Trusted) => Ok(true),
            Ok(HostKeyStatus::Changed { old_fingerprint }) => {
                *self.rejection.lock() = Some(format!(
                    "WARNUNG: Der Hostschlüssel von {}:{} hat sich geändert!\n\n\
                     Gespeichert: {old_fingerprint}\nJetzt: {fingerprint}\n\n\
                     Das kann ein Angriff (Man-in-the-Middle) sein – oder der Server wurde neu \
                     aufgesetzt. Die Verbindung wurde blockiert. Wenn die Änderung erwartet ist, \
                     den Eintrag unter „Bekannte Hosts“ entfernen.",
                    self.host, self.port
                ));
                Ok(false)
            }
            Err(e) => {
                *self.rejection.lock() = Some(format!("Datenbankfehler: {e}"));
                Ok(false)
            }
            Ok(HostKeyStatus::Unknown) => {
                let (reply, rx) = oneshot::channel();
                self.shared.set_prompt(Prompt::HostKey {
                    host: self.host.clone(),
                    port: self.port,
                    algorithm: algorithm.clone(),
                    fingerprint: fingerprint.clone(),
                    reply,
                });
                if rx.await.unwrap_or(false) {
                    if let Err(e) = self.store.lock().trust_host_key(
                        &self.host, self.port, &algorithm, &openssh, &fingerprint,
                    ) {
                        *self.rejection.lock() = Some(format!("Datenbankfehler: {e}"));
                        return Ok(false);
                    }
                    Ok(true)
                } else {
                    *self.rejection.lock() = Some("Hostschlüssel wurde abgelehnt.".into());
                    Ok(false)
                }
            }
        }
    }
}

type Handle = client::Handle<HostCheck>;

async fn ask(shared: &Shared, title: String, message: String, fields: Vec<PromptField>) -> Option<Vec<Zeroizing<String>>> {
    let (reply, rx) = oneshot::channel();
    shared.set_prompt(Prompt::Text { title, message, fields, reply });
    rx.await.ok().flatten()
}

async fn ask_one(shared: &Shared, title: String, message: String, label: &str) -> Option<Zeroizing<String>> {
    ask(shared, title, message, vec![PromptField::secret(label)]).await?.into_iter().next()
}

/// Ergebnis eines Anmeldeversuchs.
enum Outcome {
    Done,
    /// Abgelehnt; der Server akzeptiert noch diese Methoden.
    Remaining(MethodSet),
}

fn outcome(r: client::AuthResult) -> Outcome {
    match r {
        client::AuthResult::Success => Outcome::Done,
        client::AuthResult::Failure { remaining_methods, .. } => Outcome::Remaining(remaining_methods),
    }
}

async fn auth_key(
    h: &mut Handle,
    hop: &Hop,
    name: &str,
    pem: &str,
    passphrase: Option<&Zeroizing<String>>,
    shared: &Shared,
) -> Result<Outcome> {
    // Ohne gespeicherte (oder mit falscher) Passphrase wird nachgefragt.
    let mut pass = passphrase.cloned();
    let mut attempt = 0;
    let key = loop {
        match keys::decode_secret_key(pem, pass.as_ref().map(|p| p.as_str())) {
            Ok(k) => break k,
            Err(e) if crate::keys::is_encrypted(pem) => {
                let _ = e;
                attempt += 1;
                if attempt > MAX_ATTEMPTS {
                    bail!("Passphrase für Schlüssel „{name}“ ist falsch");
                }
                let msg = if pass.is_some() { "Die Passphrase war falsch." } else { "" };
                pass = Some(
                    ask_one(shared, format!("Passphrase für „{name}“"), msg.into(), "Passphrase")
                        .await
                        .ok_or_else(|| anyhow!("Anmeldung abgebrochen"))?,
                );
            }
            Err(e) => bail!("Schlüssel „{name}“ kann nicht gelesen werden: {e}"),
        }
    };
    let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
    Ok(outcome(h.authenticate_publickey(&hop.username, key).await.context("Anmeldung per Schlüssel")?))
}

async fn auth_agent(h: &mut Handle, hop: &Hop, socket: Option<&std::path::Path>) -> Result<Outcome> {
    let socket = socket.ok_or_else(|| anyhow!("Es läuft kein SSH-Agent (SSH_AUTH_SOCK ist nicht gesetzt)"))?;
    let mut agent = AgentClient::connect_uds(socket)
        .await
        .map_err(|e| anyhow!("SSH-Agent nicht erreichbar: {e}"))?;
    let identities = agent.request_identities().await.map_err(|e| anyhow!("SSH-Agent: {e}"))?;
    if identities.is_empty() {
        bail!("Der SSH-Agent enthält keine Schlüssel");
    }
    let hash = h.best_supported_rsa_hash().await.ok().flatten().flatten();
    let mut last = Outcome::Remaining(MethodSet::empty());
    for identity in identities {
        let public = identity.public_key().into_owned();
        let r = h
            .authenticate_publickey_with(&hop.username, public, hash, &mut agent)
            .await
            .map_err(|e| anyhow!("SSH-Agent: {e}"))?;
        last = outcome(r);
        if matches!(last, Outcome::Done) {
            break;
        }
    }
    Ok(last)
}

async fn auth_keyboard_interactive(h: &mut Handle, hop: &Hop, shared: &Shared) -> Result<Outcome> {
    let mut resp = h
        .authenticate_keyboard_interactive_start(&hop.username, None)
        .await
        .context("Interaktive Anmeldung")?;
    loop {
        match resp {
            KiResp::Success => return Ok(Outcome::Done),
            KiResp::Failure { remaining_methods, .. } => return Ok(Outcome::Remaining(remaining_methods)),
            KiResp::InfoRequest { name, instructions, prompts } => {
                let answers = if prompts.is_empty() {
                    Vec::new()
                } else {
                    let title = if name.is_empty() { format!("Anmeldung an {}", hop.label) } else { name };
                    let fields = prompts
                        .iter()
                        .map(|p| PromptField::new(p.prompt.trim_end(), p.echo))
                        .collect();
                    ask(shared, title, instructions, fields)
                        .await
                        .ok_or_else(|| anyhow!("Anmeldung abgebrochen"))?
                };
                let answers = answers.iter().map(|a| a.as_str().to_owned()).collect();
                resp = h
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .context("Interaktive Anmeldung")?;
            }
        }
    }
}

async fn authenticate(h: &mut Handle, hop: &Hop, shared: &Shared) -> Result<()> {
    let mut stored_password: Option<Zeroizing<String>> = None;
    let first = match &hop.auth {
        HopAuth::Key { name, pem, passphrase } => {
            auth_key(h, hop, name, pem, passphrase.as_ref(), shared).await?
        }
        HopAuth::Agent(socket) => auth_agent(h, hop, socket.as_deref()).await?,
        HopAuth::Password(saved) => {
            stored_password = saved.clone();
            // Listet der Server seine Methoden noch nicht auf, liefert „none“ sie uns.
            outcome(h.authenticate_none(&hop.username).await.context("Anmeldung")?)
        }
        HopAuth::Interactive => outcome(h.authenticate_none(&hop.username).await.context("Anmeldung")?),
    };
    let mut methods = match first {
        Outcome::Done => return Ok(()),
        Outcome::Remaining(m) => m,
    };

    // Rückfall wie bei OpenSSH: Passwort oder Rückfragen, solange der Server sie anbietet.
    // Deckt auch Zwei-Faktor-Anmeldungen ab (Schlüssel + Einmalcode).
    let mut failed = 0;
    let mut wrong_password = false;
    while failed < MAX_ATTEMPTS {
        let can_password = methods.contains(&MethodKind::Password);
        let can_ki = methods.contains(&MethodKind::KeyboardInteractive);
        let next = if can_password && (stored_password.is_some() || !can_ki) {
            let pw = match stored_password.take() {
                Some(p) => p,
                None => {
                    let msg = if wrong_password { "Das Passwort war falsch." } else { "" };
                    ask_one(
                        shared,
                        format!("Passwort für {}@{}", hop.username, hop.host),
                        msg.into(),
                        "Passwort",
                    )
                    .await
                    .ok_or_else(|| anyhow!("Anmeldung abgebrochen"))?
                }
            };
            wrong_password = true;
            outcome(h.authenticate_password(&hop.username, pw.as_str()).await.context("Anmeldung per Passwort")?)
        } else if can_ki {
            auth_keyboard_interactive(h, hop, shared).await?
        } else {
            break;
        };
        match next {
            Outcome::Done => return Ok(()),
            Outcome::Remaining(m) => methods = m,
        }
        failed += 1;
    }
    let offered: Vec<&str> = methods.iter().map(<&str>::from).collect();
    bail!(
        "Anmeldung an {} als „{}“ fehlgeschlagen.\nDer Server akzeptiert: {}",
        hop.label,
        hop.username,
        if offered.is_empty() { "–".to_string() } else { offered.join(", ") }
    )
}

fn explain(e: russh::Error, rejection: &Mutex<Option<String>>, hop: &Hop) -> anyhow::Error {
    if let Some(msg) = rejection.lock().take() {
        return anyhow!(msg);
    }
    anyhow!("Verbindung zu {}:{} fehlgeschlagen: {e}", hop.host, hop.port)
}

/// Baut die Kette der Stationen auf. Die Handles müssen am Leben bleiben.
async fn establish(plan: &Plan, shared: &Arc<Shared>, store: &Arc<Mutex<Store>>) -> Result<Vec<Handle>> {
    let mut handles: Vec<Handle> = Vec::with_capacity(plan.hops.len());
    for hop in &plan.hops {
        shared.set_status(Status::Connecting(format!("Verbinde mit {}…", hop.label)));
        let config = Arc::new(client::Config {
            keepalive_interval: (hop.keepalive_secs > 0)
                .then(|| Duration::from_secs(hop.keepalive_secs.into())),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        });
        let rejection = Arc::new(Mutex::new(None));
        let handler = HostCheck {
            host: hop.host.clone(),
            port: hop.port,
            store: store.clone(),
            shared: shared.clone(),
            rejection: rejection.clone(),
        };
        // Nur der Verbindungsaufbau hat ein Zeitlimit: Rückfragen an den Benutzer dürfen dauern.
        let mut handle = match handles.last() {
            None => {
                let tcp = tokio::time::timeout(
                    TCP_TIMEOUT,
                    tokio::net::TcpStream::connect((hop.host.as_str(), hop.port)),
                )
                .await
                .map_err(|_| anyhow!("Zeitüberschreitung beim Verbinden mit {}:{}", hop.host, hop.port))?
                .with_context(|| format!("Verbindung zu {}:{} fehlgeschlagen", hop.host, hop.port))?;
                let _ = tcp.set_nodelay(true);
                client::connect_stream(config, tcp, handler)
                    .await
                    .map_err(|e| explain(e, &rejection, hop))?
            }
            Some(prev) => {
                let channel = tokio::time::timeout(
                    TCP_TIMEOUT,
                    prev.channel_open_direct_tcpip(hop.host.clone(), hop.port as u32, "127.0.0.1", 0),
                )
                .await
                .map_err(|_| anyhow!("Zeitüberschreitung beim Tunnel zu {}:{}", hop.host, hop.port))?
                .with_context(|| format!("Tunnel zu {}:{} fehlgeschlagen", hop.host, hop.port))?;
                client::connect_stream(config, channel.into_stream(), handler)
                    .await
                    .map_err(|e| explain(e, &rejection, hop))?
            }
        };
        shared.set_status(Status::Connecting(format!("Anmeldung an {}…", hop.label)));
        authenticate(&mut handle, hop, shared).await?;
        handles.push(handle);
    }
    Ok(handles)
}

async fn run_inner(
    plan: Plan,
    shared: Arc<Shared>,
    store: Arc<Mutex<Store>>,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
) -> Result<String> {
    let handles = establish(&plan, &shared, &store).await?;
    let target = handles.last().context("Keine Verbindung")?;
    let channel = target.channel_open_session().await.context("Kanal öffnen")?;

    let (cols, rows, px_w, px_h) = shared.size();
    channel
        .request_pty(true, "xterm-256color", cols.into(), rows.into(), px_w.into(), px_h.into(), &[])
        .await
        .context("Terminal anfordern")?;
    channel.request_shell(true).await.context("Shell starten")?;
    if !plan.startup_cmd.trim().is_empty() {
        let mut line = plan.startup_cmd.trim_end().as_bytes().to_vec();
        line.push(b'\n');
        channel.data_bytes(line).await.context("Startbefehl senden")?;
    }
    shared.set_status(Status::Connected);

    // Lesen und Schreiben getrennt: eine volle Sende-Warteschlange darf die Ausgabe nie blockieren.
    let (mut read, write) = channel.split();
    let writer = tokio::spawn(async move {
        while let Some(cmd) = cmds.recv().await {
            let ok = match cmd {
                Cmd::Input(b) => write.data_bytes(b).await.is_ok(),
                Cmd::Resize { cols, rows, px_w, px_h } => {
                    write.window_change(cols.into(), rows.into(), px_w.into(), px_h.into()).await.is_ok()
                }
                Cmd::Close => {
                    let _ = write.close().await;
                    false
                }
            };
            if !ok {
                break;
            }
        }
    });

    let mut exit = None;
    let mut eof = false;
    loop {
        // Der Exit-Code kommt oft erst nach dem EOF. Danach aber nicht ewig warten,
        // falls ein Server den Kanal nie schließt.
        let msg = if eof {
            match tokio::time::timeout(Duration::from_secs(2), read.wait()).await {
                Ok(m) => m,
                Err(_) => break,
            }
        } else {
            read.wait().await
        };
        match msg {
            Some(ChannelMsg::Data { data }) => shared.feed(&data),
            Some(ChannelMsg::ExtendedData { data, .. }) => shared.feed(&data),
            Some(ChannelMsg::ExitStatus { exit_status }) => exit = Some(exit_status),
            Some(ChannelMsg::Eof) => eof = true,
            Some(ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }
    writer.abort();
    for h in handles.iter().rev() {
        let _ = h.disconnect(russh::Disconnect::ByApplication, "", "de").await;
    }
    Ok(match exit {
        Some(0) | None => "Verbindung beendet".to_string(),
        Some(code) => format!("Verbindung beendet (Exit-Code {code})"),
    })
}

/// Startet eine Sitzung im Hintergrund.
pub fn spawn(
    rt: &tokio::runtime::Handle,
    plan: Plan,
    shared: Arc<Shared>,
    store: Arc<Mutex<Store>>,
    cmds: mpsc::UnboundedReceiver<Cmd>,
) -> tokio::task::AbortHandle {
    rt.spawn(async move {
        let status = match run_inner(plan, shared.clone(), store, cmds).await {
            Ok(msg) => Status::Closed(msg),
            Err(e) => Status::Failed(format!("{e:#}")),
        };
        shared.clear_prompt();
        shared.set_status(status);
    })
    .abort_handle()
}
