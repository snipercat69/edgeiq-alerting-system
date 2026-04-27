# EdgeIQ Alerting System

A modular, standalone webhook routing layer for the EdgeIQ tool suite. Feed in structured JSON alerts and route them to Slack, Telegram, Discord, Email (SMTP), and generic HTTP webhooks — all without external Python dependencies.

---

## Features

- **5 channel types**: Slack, Telegram, Discord, Email, generic Webhook
- **Stdlib-only** — no `pip install` needed
- **Deduplication** — skips repeat alerts within a 5-minute window (content hash)
- **Per-channel rate limiting** — flat-file, 100 alerts/minute by default
- **HMAC-signed webhooks** — optional `X-EdgeIQ-Signature` header
- **Dry-run mode** — validate payloads without sending
- **One-shot mode** — pipe JSON in, alerts go out, process exits (cron-friendly)
- **Graceful error isolation** — one channel failing doesn't block others

---

## Quick Start

### 1. Clone / Copy into your project

```bash
git clone https://github.com/edgeiq/edgeiq-alerting-system.git
cd edgeiq-alerting-system
```

### 2. Configure

```bash
cp config.json.example config.json
# Edit config.json with your webhook URLs, SMTP credentials, etc.
```

### 3. Send an alert

```bash
# Via CLI argument
python3 scripts/alerter.py --payload '{
  "source": "edgeiq-xss-scanner",
  "severity": "critical",
  "title": "XSS found in /search",
  "message": "Reflected XSS in query parameter on example.com",
  "target": "https://example.com/search?q=test"
}'

# Via stdin (pipeline / cron friendly)
cat scan-output.json | python3 scripts/alerter.py
```

---

## Alert Payload Schema

```json
{
  "source": "edgeiq-xss-scanner",
  "severity": "critical",
  "title": "XSS vulnerability detected",
  "message": "Reflected XSS in parameter 'q' on /search",
  "target": "https://example.com/search?q=test",
  "timestamp": "2026-04-23T15:00:00Z",
  "tags": ["xss", "web", "example.com"],
  "data": {
    "cwe": "CWE-79",
    "cvss": "7.2"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `source` | Yes | Tool that generated the alert. One of: `edgeiq-xss-scanner`, `edgeiq-network-scanner`, `ssl-watcher`, `custom` |
| `severity` | Yes | One of: `critical`, `warning`, `info` |
| `title` | Yes | Short alert title |
| `message` | Yes | Detailed message |
| `target` | Yes | URL, host, or IP being scanned/reported |
| `timestamp` | No | ISO8601 string. Defaults to now. |
| `tags` | No | Array of string tags |
| `data` | No | Arbitrary extra key/value data |

---

## Configuration (`config.json`)

### Slack

```json
"slack": {
  "webhook_url": "https://hooks.slack.com/services/..."
}
```

Sends a rich Slack message with a header block, structured fields, optional data block, and a footer.

### Telegram

```json
"telegram": {
  "bot_token": "123456:ABCdef...",
  "chat_id": "-1001234567890"
}
```

Sends HTML-formatted messages. Create a bot via `@BotFather` and get your chat ID via `@userinfobot` or your channel.

### Discord

```json
"discord": {
  "webhook_url": "https://discord.com/api/webhooks/..."
}
```

Sends a rich Discord embed with color-coded severity, structured fields, and optional extra data.

### Email

```json
"email": {
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_user": "alerts@example.com",
  "smtp_pass": "your-app-password",
  "from_addr": "alerts@example.com",
  "to_addrs": ["team@example.com"],
  "use_tls": true
}
```

Sends a multipart MIME email (plain + HTML) with severity badge, structured table, and optional raw data.

> For Gmail, use an [App Password](https://support.google.com/accounts/answer/185833) rather than your real password.

### Generic Webhook

```json
"webhook": {
  "url": "https://your-endpoint.example.com/webhook",
  "secret": "your-hmac-secret",
  "include_raw_payload": true
}
```

POSTs a JSON payload. If `secret` is set, includes `X-EdgeIQ-Signature: sha256=<hmac_hex>` header.

---

## Rate Limiting

Default: 100 alerts/minute per channel. Configurable per channel:

```json
"rate_limit_per_channel": {
  "slack": 100,
  "telegram": 100
}
```

State is stored in `.alerter_ratelimit.json` (flat file). Deleting the file resets counters.

---

## Deduplication

Duplicate alerts (same source + title + target + message) within 5 minutes are skipped automatically. The 5-minute window is not configurable in v1.0.0. State is stored in `.alerter_dedup.json`.

---

## Dry-Run Mode

Test your alert without sending to any channel:

```bash
python3 scripts/alerter.py --dry-run --payload '{
  "source": "edgeiq-network-scanner",
  "severity": "warning",
  "title": "Open port detected",
  "message": "Port 22 is open on 10.0.0.1",
  "target": "10.0.0.1"
}'
```

Output shows what would be sent, channel by channel, without any network calls.

---

## Integration Examples

### From another EdgeIQ Python tool

```python
import subprocess, json

alert = {
    "source": "edgeiq-network-scanner",
    "severity": "info",
    "title": "Scan complete",
    "message": "50 hosts scanned, 3 open ports found",
    "target": "10.0.0.0/24"
}

result = subprocess.run(
    ["python3", "scripts/alerter.py"],
    input=json.dumps(alert),
    capture_output=True, text=True
)
print(result.stdout)
print(result.stderr)
```

### From a shell script after `nmap`

```bash
#!/bin/bash
# Run scan, capture results, send if issues found
python3 scripts/alerter.py --payload "$(cat /tmp/latest-scan.json)"
```

### Cron: nightly SSL certificate check

```cron
# Run ssl-watcher at 3am, pipe results to alerter
0 3 * * * python3 /opt/edgeiq/ssl-watcher.py | python3 /opt/edgeiq/scripts/alerter.py
```

### Cron: scheduled network scan results

```cron
# Every Monday at 9am, scan and alert
0 9 * * 1 cd /opt/edgeiq && python3 network-scanner.py --target 10.0.0.0/24 > /tmp/scan.json && cat /tmp/scan.json | python3 scripts/alerter.py --config /opt/edgeiq/config.json
```

### GitHub Actions

```yaml
- name: Run security scan
  run: python3 scanner.py --target ${{ github.event.client_payload.url }}

- name: Send alert on critical finding
  if: steps.scan.outputs.severity == 'critical'
  run: |
    python3 scripts/alerter.py --payload '{
      "source": "ci-scanner",
      "severity": "critical",
      "title": "Security issue in ${{ github.sha }}",
      "message": "${{ steps.scan.outputs.summary }}",
      "target": "${{ github.event.client_payload.url }}"
    }'
```

---

## File Layout

```
edgeiq-alerting-system/
├── SKILL.md               ← ClawHub skill metadata
├── README.md             ← This file
├── config.json.example    ← Annotated config template
├── .env.example           ← Environment variable template
├── sample-alert.json      ← Example alert for testing
└── scripts/
    └── alerter.py         ← Main application (stdlib-only)
```

---

## Troubleshooting

**"No active channels found"**
: At least one channel must have real credentials. Check that `webhook_url`, `bot_token`, `smtp_host`, etc. are filled in `config.json`.

**"Rate limited"**
: You've hit the per-minute limit for that channel. Wait ~60 seconds or delete the `.alerter_ratelimit.json` file to reset counters (not recommended in production).

**Telegram `400 Bad Request`**
: Verify your `chat_id` is correct (must be numeric, negative for groups). Test with `@userinfobot` to get your personal ID first.

**Gmail authentication fails**
: Gmail requires an [App Password](https://support.google.com/accounts/answer/185833), not your main account password. Enable 2FA first.

**Duplicate alerts not being deduplicated**
: Ensure the `source`, `title`, `target`, and `message` fields are byte-for-byte identical. Whitespace differences count as different content.

---

## Security Notes

- Keep `config.json` (and `.env`) out of version control. Add them to `.gitignore`.
- For generic webhooks, enable HMAC verification on your receiver side using the configured `secret`.
- Rate limit files (`.alerter_ratelimit.json`, `.alerter_dedup.json`) are stored in the working directory. Use a dedicated directory for the alerter to avoid polluting other project directories.

---

## License

EdgeIQ Labs. For internal use in legitimate security testing and monitoring workflows only.
