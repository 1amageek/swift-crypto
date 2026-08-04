#!/bin/bash

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <timeout-seconds> <command> [arguments ...]" >&2
    exit 2
fi

timeout_seconds="$1"
shift

if ! [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || (( timeout_seconds < 1 || timeout_seconds > 600 )); then
    echo "error: timeout must be an integer from 1 through 600 seconds" >&2
    exit 2
fi

python3 - "$timeout_seconds" "$PWD" "$@" <<'PY'
import os
import signal
import subprocess
import sys

timeout_seconds = int(sys.argv[1])
working_directory = sys.argv[2]
command = sys.argv[3:]
process = subprocess.Popen(command, cwd=working_directory, start_new_session=True)

try:
    raise SystemExit(process.wait(timeout=timeout_seconds))
except subprocess.TimeoutExpired:
    print(
        f"error: command exceeded {timeout_seconds} seconds: {' '.join(command)}",
        file=sys.stderr,
    )
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    raise SystemExit(124)
PY
