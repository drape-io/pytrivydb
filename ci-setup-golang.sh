#!/usr/bin/env sh
# Install Go toolchain for cibuildwheel (Linux containers don't bring one).
# Adapted from cloud-custodian/tfparse.
set -eu

OS=$(uname -s)
ARCH=$(uname -m)
GOVER="1.25.4"

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
esac
case "$OS" in
    Darwin) OS="darwin" ;;
    Linux)  OS="linux"  ;;
esac

curl "https://go.dev/dl/go${GOVER}.${OS}-${ARCH}.tar.gz" --silent --location | tar -xz
export PATH="$(pwd)/go/bin:$PATH"
go version
