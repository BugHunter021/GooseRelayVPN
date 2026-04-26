#!/usr/bin/env bash
# Generate a 32-byte AES-256 key, hex-encoded.
# Paste the output into both client_config.json and server_config.json (aes_key_hex).
openssl rand -hex 32
