#!/usr/bin/env bash
set -euo pipefail

docker ps --format '{{.ID}} {{.Names}}' | while read -r id name; do
    if docker exec "$id" sh -c 'ps aux | grep -E "[n]ginx" >/dev/null'; then
        echo "$name ($id):"
        docker exec "$id" ps aux | grep -E '[n]ginx'
    fi
done