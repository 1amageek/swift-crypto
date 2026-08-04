#!/bin/bash

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: $0 <source-path> [...]" >&2
    exit 2
fi

status=0
for source_path in "$@"; do
    [[ -e "$source_path" ]] || continue
    if rg --pcre2 --multiline --line-number \
        'deinit\s*\{(?s:.*?)\b(syncShutdownGracefully|wait\(\)|semaphore\.wait)\b' \
        "$source_path"; then
        status=1
    fi
done

if [[ $status -ne 0 ]]; then
    echo "error: synchronous shutdown or waiting was found in deinit" >&2
fi

exit "$status"

