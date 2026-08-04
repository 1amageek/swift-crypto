#!/bin/bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <timeout-seconds> [xcodebuild-test-arguments ...]" >&2
    exit 2
fi

timeout_seconds="$1"
shift

if ! [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || (( timeout_seconds < 1 || timeout_seconds > 120 )); then
    echo "error: timeout must be an integer from 1 through 120 seconds" >&2
    exit 2
fi

scripts/run-with-timeout.sh "$timeout_seconds" xcodebuild test "$@"
