#!/usr/bin/env bash
set -euo pipefail

separator() {
    echo -e "\n--- $1 ---"
}

separator "Running pre-commit hooks"
pre-commit run -a --show-diff-on-failure

separator "Running clang format"
make format

separator "Scanning for secrets"
gitleaks git -v
