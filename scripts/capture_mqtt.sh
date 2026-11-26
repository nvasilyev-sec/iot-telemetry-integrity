#!/usr/bin/env bash
# Optional integration for a TLS broker you own or are authorized to use.
set -euo pipefail
if [[ $# != 6 ]]; then
  echo 'Usage: bash scripts/capture_mqtt.sh HOST TOPIC CA_CERT CLIENT_CERT CLIENT_KEY COUNT' >&2
  exit 2
fi
host=$1; topic=$2; ca=$3; cert=$4; key=$5; count=$6
[[ "$count" =~ ^[1-9][0-9]*$ ]] || { echo 'COUNT must be a positive integer' >&2; exit 2; }
# Output is stdout. Do not use wildcards or retained topics for a controlled capture.
# Server identity verification is enabled; no --insecure flag.
mosquitto_sub -h "$host" -p 8883 --cafile "$ca" --cert "$cert" --key "$key" -t "$topic" -q 1 -C "$count"
