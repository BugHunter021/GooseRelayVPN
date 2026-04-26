# relay-tunnel

University showcase of **RelayHTTPS**: an AES-tunneled SOCKS5 VPN that fronts its traffic through a Google Apps Script web app, which forwards the bytes verbatim to a DigitalOcean exit server. To a passive observer, the client only ever talks TLS to a Google IP with `SNI=www.google.com`. The DO server does the real `net.Dial` to the requested target.

```
Browser/App
  -> SOCKS5 (127.0.0.1:1080)
  -> AES-256-GCM raw-TCP frames
  -> HTTPS to a Google edge IP (SNI=www.google.com, Host=script.google.com)
  -> Apps Script doPost(): forward bytes verbatim to DO via UrlFetchApp
  -> DO :8443/tunnel decrypts, demuxes by session_id, dials real target
  <- Same path in reverse (long-poll: DO holds request open ~25s for downstream)
```

## Layout

```
cmd/{client,server}/main.go      Entry points
internal/frame                   Wire format + AES-GCM seal/open + batch packer
internal/session                 Per-connection state, seq counters, rx/tx queues
internal/socks                   SOCKS5 listener + VirtualConn (net.Conn adapter)
internal/carrier                 Long-poll loop + domain-fronted HTTPS client
internal/exit                    DO HTTP handler: decrypt, demux, dial upstream
internal/config                  JSON config loaders
apps_script/Code.gs              ~30-line forwarder
scripts/gen-key.sh               openssl rand -hex 32
```

## Build

```
go build ./cmd/client
go build ./cmd/server
go test ./...
```

## End-to-end demo

1. Generate the AES-256 key:

   ```
   bash scripts/gen-key.sh
   ```

   Paste the hex string into `aes_key_hex` in **both** config files.

2. Copy the example configs and fill them in:

   ```
   cp client_config.example.json client_config.json
   cp server_config.example.json server_config.json
   ```

   In `client_config.json` set `script_url` to your Apps Script `/exec` URL.

3. Deploy `apps_script/Code.gs` as a Google Apps Script web app:
   - Execute as: **Me**
   - Access: **Anyone**
   - Set `DO_URL` at the top of the script to your DigitalOcean droplet IP.
   - Copy the deployment URL into `client_config.json`.

4. On the droplet:

   ```
   ./server -config server_config.json
   ```

5. Locally:

   ```
   ./client -config client_config.json
   ```

6. Test:

   ```
   curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
   curl -x socks5h://127.0.0.1:1080 https://example.com
   ```

   The first call should return your DO droplet's IP. Browse normally by configuring Firefox SOCKS5 to `127.0.0.1:1080` (DNS through proxy).

## Design notes

- **Frame format** (plaintext, before AES-GCM):
  `session_id (16) || seq (u64 BE) || flags (u8) || target_len (u8) || target || payload_len (u32 BE) || payload`
- **Envelope** (AES-GCM): `nonce (12) || ciphertext+tag`. Nonce per frame, AAD empty.
- **HTTP body**: `[u16 frame_count] [u32 frame_len][envelope] ...`, then base64-encoded so it survives Apps Script's `ContentService` text round-trip.
- **Long-poll**: DO holds each request open up to ~25s waiting for downstream bytes. Apps Script's `UrlFetchApp` default timeout (~60s) gives plenty of headroom.
- **Auth**: AES-GCM tag is the only authentication. Frames that fail `Open()` are dropped silently. The pre-shared key never touches Apps Script.
- **DNS**: SOCKS5 server uses a no-op resolver; clients must use `socks5h://` to push DNS through the tunnel.

## Non-goals (v1)

- Per-session ECDH (static PSK only).
- Apps Script deployment rotation or quota handling.
- Multi-user rate limiting.
- Android/`gomobile` packaging (the core is written gomobile-friendly).
- GUI.

See [plan.md](../plan.md) at the parent directory for the full design.
