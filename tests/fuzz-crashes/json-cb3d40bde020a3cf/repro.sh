#!/bin/sh
# Reproduce from the directory containing this script.
cd "$(dirname "$0")" || exit 1
env PYTHONPATH=src python3 -m sshd_lint --json sshd_config
echo "exit: $?"
