#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
PYTHON_BIN="${CPU_VALIDATION_PYTHON:-/root/.cache/uv/archive-v0/OvJCewHopHDXy8xF/bin/python}"
[[ -x "$PYTHON_BIN" ]] || { echo 'Set CPU_VALIDATION_PYTHON to a Python with PyYAML'; exit 1; }
case "${1:-}" in
  discovery) "$PYTHON_BIN" scripts/run_stage.py 01; exec "$PYTHON_BIN" scripts/run_stage.py 00 ;;
  verify) exec "$PYTHON_BIN" scripts/run_stage.py workflow ;;
  full) exec "$PYTHON_BIN" scripts/run_stage.py workflow --allow-long ;;
  *) echo 'Usage: run_all.sh discovery|verify|full'; exit 1;;
esac
