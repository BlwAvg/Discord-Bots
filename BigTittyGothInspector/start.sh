#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$ROOT_DIR/data"
LOG_FILE="$DATA_DIR/start.log"

cd "$ROOT_DIR" || exit 1

mkdir -p "$DATA_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

is_sourced() {
  [ "${BASH_SOURCE[0]}" != "$0" ]
}

open_shell_or_finish() {
  local exit_code=${1:-0}

  if is_sourced; then
    return "$exit_code"
  fi

  echo
  echo "[btgo] Start finished with exit code $exit_code."
  echo "[btgo] Log saved to $LOG_FILE"
  echo "[btgo] Opening an interactive Bash shell so the window stays open."
  echo "[btgo] Type 'exit' when you are done reading."

  export BTGO_START_EXIT_CODE="$exit_code"
  exec bash -i
}

fail() {
  local exit_code=${1:-1}
  shift
  echo "[btgo] Error: $*"
  return "$exit_code"
}

resolve_venv_python() {
  if [ -x ".venv/bin/python" ]; then
    printf '%s\n' ".venv/bin/python"
    return 0
  fi

  if [ -x ".venv/Scripts/python.exe" ]; then
    printf '%s\n' ".venv/Scripts/python.exe"
    return 0
  fi

  return 1
}

main() {
  echo "[btgo] Starting from: $ROOT_DIR"
  echo "[btgo] Log file: $LOG_FILE"

  local venv_python

  if [ ! -f ".env" ]; then
    fail 1 ".env file not found in project root. Copy .env.example to .env and fill required values first." || return $?
  fi

  if [ ! -d ".venv" ]; then
    fail 1 ".venv was not found. Run ./install.sh first." || return $?
  fi

  venv_python="$(resolve_venv_python)" || fail 1 "virtual environment python executable not found. Run ./install.sh first." || return $?

  echo "[btgo] Launching bot..."
  "$venv_python" -u bigtittygothinspector.py
}

main "$@"
open_shell_or_finish $?
