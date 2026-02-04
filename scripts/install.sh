#!/usr/bin/env bash
set -euo pipefail

log() { printf "[riphook] %s\n" "$*"; }
warn() { printf "[riphook] Warning: %s\n" "$*" >&2; }
die() { printf "[riphook] Error: %s\n" "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

OS_NAME="$(uname -s 2>/dev/null || echo unknown)"
case "$OS_NAME" in
  Darwin) PLATFORM="mac" ;;
  Linux) PLATFORM="linux" ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT) PLATFORM="windows" ;;
  *) die "Unsupported OS: ${OS_NAME}" ;;
esac

SUDO=""
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  if have sudo; then
    SUDO="sudo"
  fi
fi

install_brew() {
  if have brew; then
    return
  fi
  log "Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [ -d "/opt/homebrew/bin" ]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [ -d "/usr/local/bin" ]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
}

install_linux_packages() {
  if have apt-get; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y "$@"
    return
  fi
  if have dnf; then
    $SUDO dnf install -y "$@"
    return
  fi
  if have yum; then
    $SUDO yum install -y "$@"
    return
  fi
  if have pacman; then
    $SUDO pacman -Sy --noconfirm "$@"
    return
  fi
  if have apk; then
    $SUDO apk add --no-cache "$@"
    return
  fi
  if have zypper; then
    $SUDO zypper install -y "$@"
    return
  fi
  die "No supported Linux package manager found."
}

install_windows_pkg() {
  if have winget; then
    winget install --id "$1" --silent --accept-package-agreements --accept-source-agreements
    return
  fi
  if have choco; then
    choco install -y "$2"
    return
  fi
  die "Neither winget nor choco found. Install dependencies manually."
}

install_nvm_node() {
  if [ -z "${NVM_DIR:-}" ]; then
    export NVM_DIR="$HOME/.nvm"
  fi
  if [ ! -s "$NVM_DIR/nvm.sh" ]; then
    log "Installing nvm..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
  fi
  # shellcheck disable=SC1090
  . "$NVM_DIR/nvm.sh"
  nvm install 24
}

ensure_node() {
  if have node; then return; fi
  log "Node.js not found; installing..."
  case "$PLATFORM" in
    mac)
      install_nvm_node
      ;;
    linux)
      install_nvm_node
      ;;
    windows)
      install_windows_pkg "OpenJS.NodeJS.LTS" "nodejs-lts"
      ;;
  esac
}

ensure_npm() {
  if have npm; then return; fi
  ensure_node
  if ! have npm; then
    case "$PLATFORM" in
      linux) warn "npm missing after nvm install; you may need a new shell session." ;;
      mac) warn "npm missing after nvm install; you may need a new shell session." ;;
      windows) warn "npm missing after Node install; you may need a new shell session." ;;
    esac
  fi
}

ensure_python() {
  if have python3 || have python; then return; fi
  log "Python not found; installing..."
  case "$PLATFORM" in
    mac)
      install_brew
      brew install python
      ;;
    linux)
      if have apk; then
        install_linux_packages python3 py3-pip
      else
        install_linux_packages python3 python3-pip
      fi
      ;;
    windows)
      install_windows_pkg "Python.Python.3" "python"
      ;;
  esac
}

ensure_pip() {
  ensure_python
  local py="python3"
  if have python; then py="python"; fi
  if "$py" -m pip --version >/dev/null 2>&1; then return; fi
  warn "pip not found; bootstrapping..."
  if "$py" -m ensurepip --upgrade >/dev/null 2>&1; then
    "$py" -m pip install --upgrade pip >/dev/null 2>&1 || true
    return
  fi
  case "$PLATFORM" in
    linux)
      if have apk; then
        install_linux_packages py3-pip
      else
        install_linux_packages python3-pip
      fi
      ;;
    mac)
      install_brew
      brew install python
      ;;
    windows)
      warn "pip still missing; you may need a new shell session."
      ;;
  esac
}

ensure_pnpm() {
  if have pnpm; then return; fi
  log "pnpm not found; installing..."
  if have corepack; then
    corepack enable >/dev/null 2>&1 || true
    corepack prepare pnpm@latest --activate
    return
  fi
  ensure_npm
  npm install -g pnpm
}

ensure_tools() {
  if ! have curl; then
    log "curl not found; installing..."
    case "$PLATFORM" in
      mac) install_brew; brew install curl ;;
      linux) install_linux_packages curl ;;
      windows) warn "curl missing; please install curl and re-run." ;;
    esac
  fi
  if ! have tar; then
    log "tar not found; installing..."
    case "$PLATFORM" in
      mac) install_brew; brew install gnu-tar ;;
      linux) install_linux_packages tar ;;
      windows) warn "tar missing; please install tar and re-run." ;;
    esac
  fi
}

RIPHOOK_REPO="${RIPHOOK_REPO:-https://github.com/merciagents/riphook}"
RIPHOOK_REF="${RIPHOOK_REF:-main}"
RIPHOOK_INSTALL_DIR="${RIPHOOK_INSTALL_DIR:-$HOME/.riphook}"

fetch_repo() {
  if [ -d "$RIPHOOK_INSTALL_DIR" ]; then
    if [ -d "$RIPHOOK_INSTALL_DIR/.git" ] && have git; then
      log "Updating existing repo in $RIPHOOK_INSTALL_DIR"
      (cd "$RIPHOOK_INSTALL_DIR" && git fetch --all --tags && git checkout "$RIPHOOK_REF" && git pull --ff-only)
      return
    fi
    if [ -f "$RIPHOOK_INSTALL_DIR/package.json" ] && grep -q '"name": *"riphook"' "$RIPHOOK_INSTALL_DIR/package.json"; then
      log "Using existing install in $RIPHOOK_INSTALL_DIR"
      return
    fi
    die "Install dir exists but does not look like riphook. Set RIPHOOK_INSTALL_DIR to a different path."
  fi

  log "Downloading riphook..."
  local tmpdir
  tmpdir="$(mktemp -d)"
  local tarball="$tmpdir/riphook.tgz"
  curl -fsSL "$RIPHOOK_REPO/archive/refs/heads/$RIPHOOK_REF.tar.gz" -o "$tarball"
  tar -xzf "$tarball" -C "$tmpdir"
  local src_dir
  src_dir="$(find "$tmpdir" -maxdepth 1 -type d -name "riphook-*" | head -n 1)"
  if [ -z "$src_dir" ]; then
    die "Failed to unpack riphook archive."
  fi
  mkdir -p "$(dirname "$RIPHOOK_INSTALL_DIR")"
  mv "$src_dir" "$RIPHOOK_INSTALL_DIR"
}

log "Starting riphook installer for $PLATFORM..."
ensure_tools
ensure_node
ensure_npm
ensure_python
ensure_pip
ensure_pnpm
fetch_repo

log "Installing dependencies and configuring hooks..."
cd "$RIPHOOK_INSTALL_DIR"
if have pnpm; then
  pnpm install
else
  npm install -g pnpm
  pnpm install
fi

log "Done. Riphook installed in $RIPHOOK_INSTALL_DIR"
log "If installs were added on Windows, you may need to open a new shell session."
