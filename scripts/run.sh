#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEVICES="${DEVICES:-$REPO_ROOT/configs/devices.yaml}"
ATTACKS="${ATTACKS:-$REPO_ROOT/configs/attacks.yaml}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/data/raw}"
LOG_DIR="${LOG_DIR:-$REPO_ROOT/data/logs}"
DURATION="${DURATION:-28800}"
SAFE_PERIOD="${SAFE_PERIOD:-900}"

usage() {
    cat <<EOF
Usage:
  scripts/run.sh [options]

Options:
  --devices PATH       Path to devices YAML
  --attacks PATH       Path to attacks YAML
  --output-dir PATH    Directory for PCAP output
  --log-dir PATH       Directory for attack logs
  --duration SEC       Capture duration in seconds
  --safe-period SEC    Safe period before capture ends
  --dry-run            Validate config and print execution plan
  --verbose            Enable verbose logging
  -h, --help           Show this help
EOF
}

EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --devices)
            DEVICES="$2"
            shift 2
            ;;
        --attacks)
            ATTACKS="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --log-dir)
            LOG_DIR="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --safe-period)
            SAFE_PERIOD="$2"
            shift 2
            ;;
        --dry-run|--verbose)
            EXTRA_ARGS+=("$1")
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR" "$LOG_DIR"

cd "$REPO_ROOT"

uv run python -m capex \
    --devices "$DEVICES" \
    --attacks "$ATTACKS" \
    --output-dir "$OUTPUT_DIR" \
    --log-dir "$LOG_DIR" \
    --duration-seconds "$DURATION" \
    --safe-period-seconds "$SAFE_PERIOD" \
    "${EXTRA_ARGS[@]}"