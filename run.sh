#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/python ]]; then
  printf '%s\n' 'Python environment missing. Follow the setup instructions in README.md.' >&2
  exit 1
fi
exec .venv/bin/python app.py "$@"
