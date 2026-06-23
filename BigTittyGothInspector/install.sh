#!/usr/bin/env bash

set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$ROOT_DIR/data"
LOG_FILE="$DATA_DIR/install.log"

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
  echo "[btgo] Install finished with exit code $exit_code."
  echo "[btgo] Log saved to $LOG_FILE"
  echo "[btgo] Opening an interactive Bash shell so the window stays open."
  echo "[btgo] Type 'exit' when you are done reading."

  export BTGO_INSTALL_EXIT_CODE="$exit_code"
  exec bash -i
}

fail() {
  local exit_code=${1:-1}
  shift
  echo "[btgo] Error: $*"
  return "$exit_code"
}

run_step() {
  local description=$1
  shift

  echo "[btgo] $description"
  if ! "$@"; then
    fail 1 "$description failed."
  fi
}

find_python() {
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "python3"
    return 0
  fi

  if command -v python >/dev/null 2>&1; then
    printf '%s\n' "python"
    return 0
  fi

  return 1
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

ensure_pip() {
  local python_bin=$1

  if "$python_bin" -m pip --version >/dev/null 2>&1; then
    return 0
  fi

  if "$python_bin" -m ensurepip --version >/dev/null 2>&1; then
    run_step "Bootstrapping pip with ensurepip..." "$python_bin" -m ensurepip --upgrade
    return 0
  fi

  fail 1 "The virtual environment has no pip, and this Python install does not provide ensurepip. Install the OS package that provides venv/pip support for this Python, then delete .venv and rerun. On Debian or Ubuntu this is usually 'sudo apt install python3-venv python3-pip'."
}

main() {
  echo "[btgo] Installing from: $ROOT_DIR"
  echo "[btgo] Log file: $LOG_FILE"

  local python_bin
  local venv_python

  python_bin="$(find_python)" || fail 1 "python is not installed or not in PATH." || return $?

  if [ ! -f ".env" ]; then
    fail 1 ".env file not found in project root. Copy .env.example to .env and fill required values first." || return $?
  fi

  if [ ! -f "requirements.txt" ]; then
    fail 1 "requirements.txt was not found in the project root." || return $?
  fi

  if [ ! -d ".venv" ]; then
    run_step "Creating virtual environment..." "$python_bin" -m venv .venv || return $?
  else
    echo "[btgo] Reusing existing virtual environment."
  fi

  venv_python="$(resolve_venv_python)" || fail 1 "virtual environment python executable not found." || return $?

  ensure_pip "$venv_python" || return $?
  run_step "Upgrading pip..." "$venv_python" -m pip install --upgrade pip || return $?
  run_step "Installing requirements..." "$venv_python" -m pip install -r requirements.txt || return $?

  echo "[btgo] Install complete."
  return 0
}

main "$@"
open_shell_or_finish $?