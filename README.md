# 🔔 EdgeIQ Alerting System

**Multi-channel alert orchestration for security teams and developers.**

Route alerts from security scanners, monitoring tools, and custom applications to Slack, Telegram, email, and webhooks — with intelligent deduplication, rate limiting, and formatting.

[![Project Stage](https://img.shields.io/badge/Stage-Beta-blue)](https://edgeiqlabs.com)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-orange)](LICENSE)

---

## What It Does

Consolidates alert routing from multiple sources into a unified notification pipeline. Format alerts per-channel, deduplicate similar alerts, enforce rate limits, and ensure the right people get notified through their preferred medium.

---

## Key Features

- **Multi-channel routing** — Slack, Telegram, email (SMTP), and generic webhooks
- **Alert deduplication** — grouping similar alerts to prevent notification fatigue
- **Rate limiting** — protect notification channels from alert floods
- **Per-channel formatting** — rich formatting tailored to each platform
- **Retry logic** — failed deliveries are retried with exponential backoff
- **JSON export** — structured alert logs for audit and compliance

---

## Prerequisites

- Python 3.8 or higher
- `requests` library (`pip install requests`)
- At least one notification channel configured

---

## Installation

```bash
git clone https://github.com/snipercat69/edgeiq-alerting-system.git
cd edgeiq-alerting-system
pip install -r requirements.txt
cp config.json.example config.json
# Edit config.json with your API keys and channel settings
```

---

## Quick Start

```bash
# Send a test alert
python3 scripts/send_alert.py --channel slack --message "Security scan complete — 0 vulnerabilities"

# Send with severity
python3 scripts/send_alert.py --channel telegram --level critical --message "Unauthorized login detected"

# Use config file
python3 scripts/send_alert.py --config config.json --message "Uptime check failed"
```

---

## Configuration

Edit `config.json` with your channel credentials:

```json
{
  "channels": {
    "slack": {
      "webhook_url": "https://hooks.slack.com/services/...",
      "rate_limit": 60
    },
    "telegram": {
      "bot_token": "your_bot_token",
      "chat_id": "your_chat_id"
    }
  }
}
```

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| **Free** | $0 | 3 channels, 100 alerts/day |
| **Pro** | $15/mo | Unlimited channels, 10,000 alerts/day, priority support |
| **Lifetime** | $80 one-time | All Pro features, forever |

---

## Integration with EdgeIQ Tools

Part of the **EdgeIQ Labs** security toolkit. Works with all EdgeIQ security scanners to deliver findings:

- **[EdgeIQ XSS Scanner](https://github.com/snipercat69/edgeiq-xss-scanner)** — deliver vulnerability findings
- **[EdgeIQ Network Scanner](https://github.com/snipercat69/edgeiq-network-scanner)** — alert on new host discoveries
- **[EdgeIQ SSL Watcher](https://github.com/snipercat69/edgeiq-ssl-watcher)** — certificate expiry alerts

---

## Support

Open an issue at: https://github.com/snipercat69/edgeiq-alerting-system/issues

---

*Part of EdgeIQ Labs — [edgeiqlabs.com](https://edgeiqlabs.com)*
