#!/bin/sh
# Baut ein Binary, das auch auf älteren Distributionen läuft (ab glibc 2.28).
# Voraussetzung: zig (z. B. "sudo pacman -S zig") und cargo-zigbuild ("cargo install cargo-zigbuild").
set -eu
cd "$(dirname "$0")"
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.28
mkdir -p dist
cp target/x86_64-unknown-linux-gnu/release/sshelf dist/sshelf
echo "Fertig: dist/sshelf"
objdump -T dist/sshelf | grep '\*UND\*' | grep -v ' w ' | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1
