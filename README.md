# SSHelf

Schlanke SSH-Verbindungsverwaltung für Linux mit eingebautem Terminal: ein leichter Ersatz für
Tabby, geschrieben in Rust. Ein einzelnes Binary von rund 10 MB, ohne GTK, Qt, Electron oder ein
installiertes `ssh`.

## Funktionen

- Verbindungen anlegen, bearbeiten, duplizieren, löschen, suchen und in Gruppen ordnen;
  Gruppen lassen sich zuklappen, vorhandene Gruppen im Editor auswählen
- Seitenleiste in der Breite verstellbar und auf eine Symbolleiste einklappbar
- Fenstergröße, Maximierung und Seitenleiste werden für den nächsten Start gespeichert
- Felder: Name, Gruppe, Host, Port, Benutzer, Anmeldung, Schlüssel, Jump-Host, Keepalive,
  Startbefehl, Notizen
- Anmeldung per gespeichertem Schlüssel, Passwort, SSH-Agent oder Rückfrage (auch Einmalcodes)
- Schlüssel importieren (Datei oder Einfügen; OpenSSH, PEM, PuTTY) oder Ed25519 neu erzeugen
- Terminal mit Tabs, 10.000 Zeilen Verlauf, Maus-Unterstützung, Farben und Textauswahl
- Prüfung der Hostschlüssel: Nachfrage beim ersten Mal, Sperre bei Änderung
- Design in Nord-Farben: dunkel, hell oder wie das System
- Auf Wunsch Symbol in der Statusleiste: Fenster schließen, Verbindungen laufen weiter

## Starten

    ./sshelf                     # Standard: ~/.local/share/sshelf/sshelf.db
    ./sshelf --db pfad.db        # bestimmte Datenbank für diesen Start
    ./sshelf --config datei.ini  # andere Konfigurationsdatei

**Umzug auf einen anderen Rechner:** Binary und Datenbank kopieren. Liegt `sshelf.db` neben dem
Binary und ist kein Pfad konfiguriert, wird sie automatisch verwendet (portabler Modus).

## Konfiguration

Der Datenbankpfad und die Statusleiste lassen sich in den Einstellungen ändern oder direkt in
`~/.config/sshelf/config.ini` (Kommentare darin überschreibt die App beim Speichern):

    [database]
    path = ~/Nextcloud/sshelf.db

    [window]
    close_to_tray = true
    width = 1180
    height = 760
    maximized = false

    [sidebar]
    width = 272
    collapsed = false

    [terminal]
    font = JetBrains Mono
    size = 14

Größe, Maximierung und Seitenleiste schreibt die App beim Schließen selbst. Eine Fensterposition
(`x`, `y`) wird nur unter X11 gespeichert und gesetzt; unter Wayland legt der Fenstermanager sie
fest.

Reihenfolge für die Datenbank: `--db`, dann `path` aus der Datei, dann `sshelf.db` neben dem
Programm, dann der Standardort. Fehlt eine konfigurierte Datei beim Start (zum Beispiel weil ein
Laufwerk nicht eingehängt ist), zeigt die App eine Auswahl, statt still eine leere anzulegen.

## Programmsymbol und Anwendungsmenü

Unter Einstellungen → „Ins Anwendungsmenü eintragen“ (oder `sshelf --install-desktop`) legt
SSHelf `~/.local/share/applications/sshelf.desktop` und das Symbol
`~/.local/share/icons/hicolor/scalable/apps/sshelf.svg` an. Danach erscheint SSHelf mit Symbol
im Startmenü, in der Fensterleiste und in der Titelzeile. `--uninstall-desktop` entfernt beides.

Eine ausführbare Datei kann unter Linux kein eigenes Symbol tragen; Dateimanager zeigen dafür
immer das Symbol des Dateityps. „Starter neben dem Programm ablegen“ legt deshalb zusätzlich
`SSHelf.desktop` in den Programmordner, das im Dateimanager mit Symbol erscheint.

## Titelleiste

Titelleiste und Fensterknöpfe zeichnet der Fenstermanager (KDE, X11-Fenstermanager), dadurch
folgen sie dessen Thema, und ein Doppelklick maximiert bzw. stellt wieder her. Auf Wayland-Desktops
ohne diese Möglichkeit, etwa GNOME, zeichnet SSHelf eine eigene Titelleiste im Adwaita-Stil.

## Statusleiste

Mit `close_to_tray` schließt das Fenster, das Programm läuft mit allen Verbindungen weiter. Ein
Klick auf das Symbol öffnet das Fenster wieder, Beenden geht über dessen Menü. Der Tresor bleibt
dabei entsperrt. Das Symbol nutzt StatusNotifierItem: KDE kann das direkt, GNOME braucht die
Erweiterung „AppIndicator“. Gibt es keine solche Statusleiste, beendet das Schließen die Anwendung
wie gewohnt, damit sie nie unerreichbar wird.

## Sicherheit

- Private Schlüssel, Passphrasen und Passwörter liegen mit XChaCha20-Poly1305 verschlüsselt in der
  SQLite-Datei. Der Schlüssel dazu wird per Argon2id aus dem Master-Passwort abgeleitet.
- **Ein vergessenes Master-Passwort kann nicht wiederhergestellt werden.**
- Nicht verschlüsselt sind Namen, Hosts, Ports, Benutzer, Notizen, Startbefehle und bekannte Hosts.
- Server können die Zwischenablage nicht lesen oder schreiben (OSC 52 ist abgeschaltet).

## Tastenkürzel im Terminal

| Taste | Wirkung |
|---|---|
| Strg+Umschalt+C / V | Kopieren / Einfügen (auch Umschalt+Einfg und Rechtsklick) |
| Markieren, mittlere Maustaste | Markierten Text einfügen (Primary-Selection) |
| Strg+Tab, Strg+Bild↑/↓ | Tab wechseln |
| Strg+Umschalt+W | Tab schließen |
| Umschalt+Bild↑/↓, Mausrad | Im Verlauf blättern |
| Umschalt+Ziehen | Text auswählen, auch wenn ein Programm die Maus nutzt |
| Über den Rand ziehen | Beim Markieren scrollt der Verlauf mit, je weiter weg, desto schneller |

## Systemvoraussetzungen

Das Binary braucht glibc und lädt beim Start OpenGL/EGL, X11 oder Wayland sowie xkbcommon aus dem
System. Auf normalen Linux-Desktops ist das alles vorhanden, auf einem reinen Server ohne Desktop
nicht.

Die nötige glibc-Version hängt vom Build ab:

| Build | Mindestens | Läuft zum Beispiel auf |
|---|---|---|
| `cargo build --release` auf diesem System | glibc 2.35 | Ubuntu 22.04+, Debian 12+, aktuelle Rolling Releases |
| `./build-portable.sh` (optional, braucht zig und cargo-zigbuild, bisher ungetestet) | glibc 2.28 | zusätzlich ältere Distributionen |

Fehlt den eingebauten Schriften ein Zeichen, sucht SSHelf wie andere Terminals eine installierte
Systemschrift, die es enthält: zuerst über fontconfig, notfalls in allen installierten Schriften
(so werden auch die Icons der Nerd Fonts in Shell-Prompts gefunden). Schriften werden erst bei
Bedarf geladen. fontconfig wird zur Laufzeit nachgeladen und ist keine feste Abhängigkeit; ohne
passende Systemschrift erscheint ein Kästchen.

Die Terminalschrift lässt sich in den Einstellungen wählen; angeboten werden alle installierten
Schriften mit fester Zeichenbreite, mit Vorschau. Standard ist das eingebaute Hack. Fehlt eine
gewählte Schrift (etwa auf einem anderen Rechner), nimmt SSHelf Hack und weist darauf hin. Gerastert wird sie wie bei Konsole mit FreeType
(leichtes Hinting), das zur Laufzeit geladen wird; fehlt `libfreetype.so.6`, zeichnet egui die
Schrift etwas weicher. Zellen sind ganze Bildschirmpixel breit. Fett kommt aus dem Fettschnitt der
Familie (für das eingebaute Hack aus einem installierten Hack Bold), sonst erzeugt FreeType ihn.
Zeichen, die der Schrift fehlen, kommen über den Schriftrückfall aus Systemschriften.

Rahmen-, Block- und Braille-Zeichen (Spinner von `docker compose` oder `btop`), ✓✔✗✘ und die
Powerline-Trenner von Shell-Prompts zeichnet SSHelf selbst, damit sie lückenlos und unabhängig von
den Schriften erscheinen.

## Entwicklung

    cargo test      # Unit- und End-to-End-Tests, braucht sshd, ssh-keygen, ssh-agent und eine GPU

Mit `SSHELF_SHOTS=<ordner>` speichern die Oberflächentests Screenshots. Die Tests rendern über
wgpu; um die Darstellung im echten OpenGL-Renderer zu prüfen, gibt es eine Diagnose:

    cargo build --release --features selfshot
    SSHELF_SELFSHOT=/tmp/terminal.png target/release/sshelf

| Datei | Inhalt |
|---|---|
| `src/vault.rs` | Verschlüsselung |
| `src/store.rs` | SQLite-Datenbank |
| `src/config.rs` | INI-Konfiguration, Datenbankpfad |
| `src/tray.rs` | Symbol in der Statusleiste |
| `src/desktop.rs` | Programmsymbol, Eintrag im Anwendungsmenü |
| `src/fonts.rs` | Schriftrückfall auf Systemschriften |
| `src/glyphs.rs` | Terminalschrift mit FreeType rastern |
| `src/keys.rs` | Schlüssel prüfen und erzeugen |
| `src/ssh.rs` | Verbindungsaufbau, Anmeldung, Jump-Hosts |
| `src/term.rs` | Terminal: Eingabe und Darstellung |
| `src/app.rs` | Oberfläche |
| `src/e2e_tests.rs` | End-to-End-Tests gegen einen echten `sshd` |

## Lizenz

SSHelf steht wahlweise unter der [MIT-Lizenz](LICENSE-MIT) oder der
[Apache-Lizenz 2.0](LICENSE-APACHE). Die Lizenzen der verwendeten Bibliotheken und der
eingebetteten Schriften stehen in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
