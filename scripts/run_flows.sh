#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP_DIR="${PCAP_DIR:-$REPO_ROOT/data/raw}"
FLOW_DIR="${FLOW_DIR:-$REPO_ROOT/data/flows}"

mkdir -p "$FLOW_DIR"

shopt -s nullglob
pcap_files=("$PCAP_DIR"/*.pcap)

if [[ ${#pcap_files[@]} -eq 0 ]]; then
    echo "No .pcap files found in: $PCAP_DIR"
    exit 0
fi

cd "$REPO_ROOT"

for pcap_file in "${pcap_files[@]}"; do
    base_name="$(basename "$pcap_file" .pcap)"
    csv_file="$FLOW_DIR/${base_name}.csv"

    echo "Processing: $pcap_file -> $csv_file"
    uv run --group scripting python -m cicflowmeter.sniffer -f "$pcap_file" -c "$csv_file"
done

echo "All PCAP files processed successfully."