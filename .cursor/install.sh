#!/usr/bin/env bash
set -euo pipefail

if ! command -v tracepath >/dev/null; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iputils-tracepath traceroute
fi

go mod download
go build -o bin/traceroute-tool ./cmd/traceroute-tool
