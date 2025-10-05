#!/usr/bin/env bash
#set -eu
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH="$SCRIPT_DIR"
PYTHON_BIN="python3"
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
  PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python"
fi
export PYTHONPATH
exec "$PYTHON_BIN" "$SCRIPT_DIR/main.py" "$@"
