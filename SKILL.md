# EdgeIQ Alerting System — SKILL.md

**Skill Name:** edgeiq-alerting-system
**Version:** 1.0.0
**Category:** Infrastructure / Alerting
**Author:** EdgeIQ Labs
**ClawHub:** `edgeiq-alerting-system`

---

## Overview

EdgeIQ Alerting System is a modular, standalone webhook routing layer that collects scan results, security findings, and custom events from EdgeIQ tools and fan-outs formatted notifications to Slack, Telegram, Discord, Email (SMTP), and generic webhooks.

It is designed to be the backbone alerting infrastructure for the EdgeIQ tool suite — drop it into any pipeline, point your scanners at it, and alerts reach your team wherever they live.

---

## Tiers

| Tier | Channels | Alerts/Day | Severity Tagging | Alert Aggregation | Price |
|------|----------|------------|-------------------|-------------------|-------|
| **Free** | 1 | 100 | No | No | Free |
| **Pro** | Unlimited | Unlimited | Yes | Yes | **$9/mo** |
| **Lifetime** | Unlimited | Unlimited | Yes | Yes | **$39 (one-time)** |

> **Lifetime available:** Pay $39 once, own it forever — no recurring charges.
> [Buy Lifetime — $39](https://buy.stripe.com/28EbJ3gKv7hb3jS2cg7wA03) · [Subscribe Monthly — $9/mo](https://buy.stripe.com/28EbJ3gKv7hb3jS2cg7wA03)

---

## Features

- **Multi-channel routing** — Slack, Telegram, Discord, Email (SMTP), generic HTTP webhook
- **Structured JSON input** — unified alert schema consumed from CLI args or stdin
- **Channel-specific formatting** — Slack blocks, Telegram HTML, Discord embeds, MIME email
- **Deduplication** — skips duplicate alerts within a 5-minute window using content hashing
- **Rate limiting** — flat-file per-channel rate limiter (default 100 alerts/minute)
- **HMAC signing** — optional HMAC-SHA256 signature for generic webhook payloads
- **Dry-run mode** — validate payloads without sending to any channel
- **One-shot mode** — read JSON, send, exit (cron-friendly / pipeline-friendly)
- **Graceful per-channel error isolation** — one channel failing does not block others
- **Stdlib-only** — no external Python dependencies beyond the standard library
- **Configurable via `config.json`** — all channel credentials and settings in one place

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

All fields except `timestamp`, `tags`, and `data` are required.

---

## Usage Examples

### Piping scan output from edgeiq-xss-scanner

```bash
python3 scripts/alerter.py --payload '{"source":"edgeiq-xss-scanner","severity":"critical","title":"XSS found","message":"Reflected XSS in /search","target":"https://example.com/search?q=test"}'
```

### One-shot via stdin (pipeline-friendly)

```bash
cat scan-result.json | python3 scripts/alerter.py
```

### Dry-run (no alerts sent)

```bash
python3 scripts/alerter.py --dry-run --payload '{"source":"edgeiq-network-scanner","severity":"warning","title":"Open port detected","message":"Port 22 open on 10.0.0.1","target":"10.0.0.1"}'
```

### Cron: Nightly scan结果的自动告警

```cron
0 3 * * * cd /opt/edgeiq-alerting-system && python3 scripts/alerter.py < /tmp/scan-$(date +\%Y\%m\%d).json
```

### From another EdgeIQ tool (Python subprocess)

```python
import subprocess, json

result = {"source": "edgeiq-network-scanner", "severity": "info",
          "title": "Scan complete", "message": "50 hosts scanned",
          "target": "10.0.0.0/24"}

subprocess.run(
    ["python3", "scripts/alerter.py"],
    input=json.dumps(result),
    text=True
)
```

---

## Legal Notice

EdgeIQ Alerting System is provided as-is for legitimate security testing and monitoring workflows. Users are responsible for ensuring their use complies with applicable laws and the terms of any services they integrate with. Do not use this tool to send unsolicited messages or to conduct unauthorized access. The authors assume no liability for misuse.


---

## 🔗 More from EdgeIQ Labs

**edgeiqlabs.com** — Security tools, OSINT utilities, and micro-SaaS products for developers and security professionals.

- 🛠️ **Subdomain Hunter** — Passive subdomain enumeration via Certificate Transparency
- 📸 **Screenshot API** — URL-to-screenshot API for developers
- 🔔 **uptime.check** — URL uptime monitoring with alerts
- 🛡️ **headers.check** — HTTP security headers analyzer

👉 [Visit edgeiqlabs.com →](https://edgeiqlabs.com)
