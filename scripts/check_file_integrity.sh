#!/usr/bin/env bash
# check_file_integrity.sh - Generate or verify SHA-256 checksums for a directory
# Usage:
#   ./check_file_integrity.sh --generate --dir <path> --output <checksums.sha256>
#   ./check_file_integrity.sh --verify  --dir <path> --input  <checksums.sha256>
# Blue Team Use: Detect unauthorized file modifications

set -euo pipefail

MODE=""
DIR=""
CHECKSUM_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --generate) MODE="generate"; shift ;;
        --verify)   MODE="verify";   shift ;;
        --dir)      DIR="$2";        shift 2 ;;
        --output)   CHECKSUM_FILE="$2"; shift 2 ;;
        --input)    CHECKSUM_FILE="$2"; shift 2 ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$MODE" || -z "$DIR" || -z "$CHECKSUM_FILE" ]]; then
    echo "Usage:" >&2
    echo "  $0 --generate --dir <path> --output <file>" >&2
    echo "  $0 --verify   --dir <path> --input  <file>" >&2
    exit 1
fi

if [[ ! -d "$DIR" ]]; then
    echo "Directory not found: $DIR" >&2
    exit 1
fi

case "$MODE" in
    generate)
        echo "=== Generating checksums for: $DIR ==="
        find "$DIR" -type f -not -path "$CHECKSUM_FILE" -print0 \
            | sort -z \
            | xargs -0 sha256sum > "$CHECKSUM_FILE"
        echo "Checksums written to: $CHECKSUM_FILE"
        ;;
    verify)
        if [[ ! -f "$CHECKSUM_FILE" ]]; then
            echo "Checksum file not found: $CHECKSUM_FILE" >&2
            exit 1
        fi
        echo "=== Verifying checksums against: $DIR ==="
        FAILED=0
        while read -r EXPECTED_HASH FILEPATH; do
            if [[ ! -f "$FILEPATH" ]]; then
                echo "MISSING: $FILEPATH"
                FAILED=$((FAILED + 1))
            else
                ACTUAL_HASH="$(sha256sum "$FILEPATH" | cut -d' ' -f1)"
                if [[ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]]; then
                    echo "MODIFIED: $FILEPATH"
                    FAILED=$((FAILED + 1))
                fi
            fi
        done < "$CHECKSUM_FILE"

        if [[ "$FAILED" -eq 0 ]]; then
            echo "OK: All files match."
        else
            echo "ALERT: $FAILED file(s) failed integrity check!"
            exit 2
        fi
        ;;
esac
