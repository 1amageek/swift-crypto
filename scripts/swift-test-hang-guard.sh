#!/bin/bash

set -euo pipefail

repeats=3
test_timeout=30
build_timeout=120

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repeats)
            repeats="$2"
            shift 2
            ;;
        --timeout)
            test_timeout="$2"
            shift 2
            ;;
        --build-timeout)
            build_timeout="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "error: unknown argument $1" >&2
            exit 2
            ;;
    esac
done

for value in "$repeats" "$test_timeout" "$build_timeout"; do
    if ! [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "error: repeat and timeout values must be integers" >&2
        exit 2
    fi
done

if (( repeats < 1 || test_timeout < 1 || test_timeout > 120 || build_timeout < 1 || build_timeout > 120 )); then
    echo "error: repeats must be positive and timeouts must be within 1...120 seconds" >&2
    exit 2
fi

artifact_root=".test-artifacts/hang-guard"
lock_directory="$artifact_root/.lock"
mkdir -p "$artifact_root"
if ! mkdir "$lock_directory" 2>/dev/null; then
    echo "error: another hang-guard run is active" >&2
    exit 3
fi
trap 'rmdir "$lock_directory" 2>/dev/null || true' EXIT

run_directory="$artifact_root/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$run_directory"

list_owned_helpers() {
    ps -axo pid=,command= | awk -v root="$PWD" '
        index($0, "swiftpm-testing-helper") && index($0, root) { print }
    '
}

if [[ -n "$(list_owned_helpers)" ]]; then
    echo "error: task-owned stale testing helper exists before the run" >&2
    list_owned_helpers >"$run_directory/preexisting-helpers.txt"
    exit 1
fi

for ((run_index = 1; run_index <= repeats; run_index += 1)); do
    current_timeout="$test_timeout"
    if (( run_index == 1 )); then
        current_timeout="$build_timeout"
    fi

    log_file="$run_directory/run-$run_index.log"
    set +e
    scripts/swift-test-timeout.sh "$current_timeout" "$@" >"$log_file" 2>&1
    test_status=$?
    set -e
    if [[ $test_status -ne 0 ]]; then
        {
            echo "exit_status=$test_status"
            echo "owned_helpers:"
            list_owned_helpers
            echo "build_processes:"
            ps -axo pid=,ppid=,etime=,command= | rg "$PWD|swiftpm-testing-helper|xcodebuild" || true
            echo "build_lock:"
            ls -l .build/.lock 2>/dev/null || true
        } >"$run_directory/run-$run_index.diag.txt"
        cat "$log_file"
        exit "$test_status"
    fi

    if [[ -n "$(list_owned_helpers)" ]]; then
        list_owned_helpers >"$run_directory/run-$run_index.diag.txt"
        echo "error: task-owned stale testing helper remained after run $run_index" >&2
        exit 1
    fi
done

echo "OK: $repeats guarded runs completed without timeout or stale helper"
