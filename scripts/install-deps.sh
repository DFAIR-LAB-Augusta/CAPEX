#!/usr/bin/env bash
# Installs the system packages required by CAPEX's attack library.
# Debian/Ubuntu-based lab hosts. Run as root (or with an elevated shell).
#
# Python dependencies (pydantic, etc.) are handled separately via
# `make sync` / `uv sync --dev` - this script only covers OS-level binaries.
set -euo pipefail

apt-get update
apt-get install -y \
  tcpdump \
  nmap \
  hping3 \
  slowhttptest \
  hydra \
  dsniff

echo "Done."
echo "tcpdump, hping3, and arpspoof (from dsniff) need CAP_NET_RAW or root to run - see docs/USAGE.md."
