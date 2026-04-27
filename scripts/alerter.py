#!/usr/bin/env python3
"""
EdgeIQ Alerting System — alerter.py
A modular webhook and alerting routing layer for EdgeIQ tools.
Stdlib-only: json, smtplib, urllib, ssl, datetime, uuid, hashlib, hmac, base64, email.
"""

import sys
import os
import json
import argparse
import datetime
import uuid
import hashlib
import hmac
import base64
import email.mime.text
import email.mime.multipart
import email.header
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
import time
import re

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SKILL_VERSION = "1.0.0"
DEFAULT_CONFIG = "config.json"
RATE_LIMIT_FILE = ".alerter_ratelimit.json"
DEDUP_FILE = ".alerter_dedup.json"
DEDUP_WINDOW_SECS = 300          # 5 minutes
DEFAULT_RATE_LIMIT = 100          # alerts per minute per channel
RATE_WINDOW_SECS = 60

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
VALID_SOURCES = {
    "edgeiq-xss-scanner", "edgeiq-network-scanner", "ssl-watcher", "custom"
}
VALID_SEVERITIES = {"critical", "warning", "info"}

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    if not os.path.exists(path):
        die(f"Config file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except json.JSONDecodeError as e:
        die(f"Invalid JSON in config: {e}")
    _validate_config(cfg)
    return cfg


def _validate_config(cfg: dict) -> None:
    channels = cfg.get("channels", {})
    if not channels:
        die("Config must have at least one configured channel.")
    # At least one real channel must be present
    active = {
        "slack": bool(channels.get("slack", {}).get("webhook_url")),
        "telegram": bool(channels.get("telegram", {}).get("bot_token"))
                    and bool(channels.get("telegram", {}).get("chat_id")),
        "discord": bool(channels.get("discord", {}).get("webhook_url")),
        "email": bool(channels.get("email", {}).get("smtp_host"))
                 and bool(channels.get("email", {}).get("from_addr")),
        "webhook": bool(channels.get("webhook", {}).get("url")),
    }
    if not any(active.values()):
        die("No active channels found in config. Configure at least one channel.")


# ---------------------------------------------------------------------------
# Alert validation
# ---------------------------------------------------------------------------

def validate_alert(alert: dict) -> list[str]:
    errors = []
    required = ["source", "severity", "title", "message", "target"]
    for field in required:
        if not alert.get(field):
            errors.append(f"Missing required field: '{field}'")
    sev = alert.get("severity", "")
    if sev not in VALID_SEVERITIES:
        errors.append(f"Invalid severity '{sev}'. Must be one of: {VALID_SEVERITIES}")
    if "tags" in alert and not isinstance(alert["tags"], list):
        errors.append("Field 'tags' must be an array.")
    if "data" in alert and not isinstance(alert["data"], dict):
        errors.append("Field 'data' must be an object.")
    if "timestamp" in alert:
        ts = alert["timestamp"]
        if not _is_iso8601(ts):
            errors.append(f"timestamp '{ts}' is not a valid ISO8601 string.")
    return errors


def _is_iso8601(s: str) -> bool:
    """Rough ISO8601 check: YYYY-MM-DDTHH:MM:SS(±HH:MM|Z)."""
    pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$"
    return bool(re.match(pattern, s))


# ---------------------------------------------------------------------------
# Alert ID & deduplication
# ---------------------------------------------------------------------------

def generate_alert_id(alert: dict) -> str:
    """Stable UUID5 derived from source + title + target + message."""
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL NS
    components = [
        str(alert.get("source", "")),
        str(alert.get("title", "")),
        str(alert.get("target", "")),
        str(alert.get("message", "")),
    ]
    canonical = "|".join(components)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
    return str(uuid.UUID(namespace=namespace, name=digest))


def content_hash(alert: dict) -> str:
    """
    SHA256 of canonicalised alert content for deduplication.
    Strips 'timestamp' and 'data' from the hash input so that
    natural time differences between pipeline runs don't cause
    false non-duplicates.
    """
    sig = {k: v for k, v in alert.items() if k not in ("timestamp", "data")}
    canonical = json.dumps(sig, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def is_duplicate(content_hash_val: str, dedup_file: str) -> bool:
    """Return True if this content hash was seen within the deduplication window."""
    now = time.time()
    window = DEDUP_WINDOW_SECS
    if not os.path.exists(dedup_file):
        return False
    try:
        with open(dedup_file, "r", encoding="utf-8") as f:
            entries = json.load(f)
    except (json.JSONDecodeError, IOError):
        return False
    # Purge expired entries
    entries = {h: ts for h, ts in entries.items() if now - ts < window}
    with open(dedup_file, "w", encoding="utf-8") as f:
        json.dump(entries, f)
    return content_hash_val in entries


def mark_seen(content_hash_val: str, dedup_file: str) -> None:
    now = time.time()
    entries = {}
    if os.path.exists(dedup_file):
        try:
            with open(dedup_file, "r", encoding="utf-8") as f:
                entries = json.load(f)
        except (json.JSONDecodeError, IOError):
            entries = {}
    entries[content_hash_val] = now
    # Keep file bounded
    if len(entries) > 10000:
        cutoff = now - DEDUP_WINDOW_SECS
        entries = {h: ts for h, ts in entries.items() if ts >= cutoff}
    with open(dedup_file, "w", encoding="utf-8") as f:
        json.dump(entries, f)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def check_rate_limit(channel: str, config: dict, ratelimit_file: str) -> tuple[bool, int]:
    """
    Returns (allowed, remaining). allowed=False means rate limited.
    Tracks alerts/minute per channel using a flat-file store.
    """
    limit = config.get("rate_limit_per_channel", {}).get(channel, DEFAULT_RATE_LIMIT)
    window = RATE_WINDOW_SECS
    now = time.time()

    entries = {}
    if os.path.exists(ratelimit_file):
        try:
            with open(ratelimit_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
                # raw = {channel: [timestamp, ...]}
                entries = {ch: [ts for ts in tslist if now - ts < window]
                           for ch, tslist in raw.items()}
        except (json.JSONDecodeError, IOError):
            entries = {}

    count = len(entries.get(channel, []))
    if count >= limit:
        return False, 0

    entries.setdefault(channel, []).append(now)
    # Prune old entries across all channels
    pruned = {ch: [ts for ts in tslist if now - ts < window]
              for ch, tslist in entries.items()}
    with open(ratelimit_file, "w", encoding="utf-8") as f:
        json.dump(pruned, f)

    remaining = limit - count - 1
    return True, max(0, remaining)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _fmt_timestamp(alert: dict) -> str:
    ts = alert.get("timestamp")
    if ts:
        try:
            dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return ts
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_emoji(sev: str) -> str:
    return {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(sev, "⚪")


def _severity_label(sev: str) -> str:
    return {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO"}.get(sev, "UNKNOWN")


# Slack
def format_slack(alert: dict) -> dict:
    emoji = _severity_emoji(alert["severity"])
    title = _escape_slack(alert["title"])
    message = _escape_slack(alert["message"])
    source = alert.get("source", "custom")
    target = _escape_slack(alert.get("target", "—"))
    ts = _fmt_timestamp(alert)
    tags = ", ".join(alert.get("tags", [])) or "None"

    text = (
        f"{emoji} *[{source}]* {emoji}\n"
        f"*Severity:* `{alert['severity'].upper()}`\n"
        f"*Title:* {title}\n"
        f"*Message:* {message}\n"
        f"*Target:* `{target}`\n"
        f"*Time:* {ts}\n"
        f"*Tags:* {tags}"
    )

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {alert['title']}", "emoji": True}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Source:*\n{source}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n`{alert['severity'].upper()}`"},
                {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                {"type": "mrkdwn", "text": f"*Time:*\n{ts}"},
            ]
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Message:*\n{message}"}},
    ]

    if alert.get("data"):
        data_str = _escape_slack(json.dumps(alert["data"], indent=2, default=str))
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Extra Data:*\n```{data_str}```"}})

    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"_Tags: {tags}_ | EdgeIQ Alerting System v{SKILL_VERSION}_"}]})

    return {"text": text, "blocks": blocks}


def _escape_slack(text: str) -> str:
    return (text.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


# Telegram
def format_telegram(alert: dict) -> dict:
    emoji = _severity_emoji(alert["severity"])
    sev_label = _severity_label(alert["severity"])
    title = alert["title"]
    message = alert["message"]
    source = alert.get("source", "custom")
    target = alert.get("target", "—")
    ts = _fmt_timestamp(alert)
    tags = " ".join(f"#{t}" for t in alert.get("tags", []))

    html = (
        f"<b>{emoji} {title}</b>\n\n"
        f"<b>Source:</b> <code>{_escape_html(source)}</code>\n"
        f"<b>Severity:</b> <code>{sev_label}</code>\n"
        f"<b>Target:</b> <code>{_escape_html(target)}</code>\n"
        f"<b>Time:</b> <code>{ts}</code>\n\n"
        f"<b>Message:</b>\n{_escape_html(message)}\n"
    )
    if tags:
        html += f"\n<i>{tags}</i>"
    if alert.get("data"):
        html += f"\n\n<b>Extra Data:</b>\n<code>{_escape_html(json.dumps(alert['data'], default=str))}</code>"

    return {"html": html}


def _escape_html(text: str) -> str:
    return (text.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;"))


# Discord
def format_discord(alert: dict) -> dict:
    color_map = {"critical": 0xFF0000, "warning": 0xFFAA00, "info": 0x3498DB}
    color = color_map.get(alert["severity"], 0x808080)
    ts = alert.get("timestamp")
    if not ts:
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    fields = [
        {"name": "Source", "value": alert.get("source", "custom"), "inline": True},
        {"name": "Target", "value": alert.get("target", "—"), "inline": True},
        {"name": "Severity", "value": alert["severity"].upper(), "inline": True},
    ]
    if alert.get("tags"):
        fields.append({"name": "Tags", "value": " ".join(f"`{t}`" for t in alert["tags"]), "inline": False})

    embed = {
        "title": f"{_severity_emoji(alert['severity'])} {alert['title']}",
        "description": alert["message"],
        "color": color,
        "fields": fields,
        "footer": {"text": f"EdgeIQ Alerting System v{SKILL_VERSION}"},
        "timestamp": ts,
    }
    if alert.get("data"):
        embed["fields"].append({
            "name": "Extra Data",
            "value": f"```json\n{json.dumps(alert['data'], default=str)}\n```",
            "inline": False
        })

    return {"embeds": [embed]}


# Email
def format_email(alert: dict, cfg: dict) -> dict:
    email_cfg = cfg.get("channels", {}).get("email", {})
    from_addr = email_cfg.get("from_addr", "alerts@edgeiq.local")
    to_addrs = email_cfg.get("to_addrs", [])
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]

    subject_prefix = {"critical": "🚨 CRITICAL", "warning": "⚠️ WARNING", "info": "ℹ️ INFO"}.get(alert["severity"], "📢")
    subject = f"{subject_prefix} [{alert.get('source','custom')}] {alert['title']}"

    ts = _fmt_timestamp(alert)
    target = alert.get("target", "—")
    tags = ", ".join(alert.get("tags", [])) or "None"

    html_body = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 700px; margin: auto;">
<h2 style="color: #2c3e50;">{_escape_html(alert['title'])}</h2>
<table style="width: 100%; border-collapse: collapse;">
  <tr><td style="padding: 6px; font-weight: bold; width: 120px;">Source</td>
      <td style="padding: 6px;">{_escape_html(alert.get('source','custom'))}</td></tr>
  <tr><td style="padding: 6px; font-weight: bold;">Severity</td>
      <td style="padding: 6px;"><span style="background: #{'e74c3c' if alert['severity']=='critical' else 'f39c12' if alert['severity']=='warning' else '3498db'};
                             color: white; padding: 2px 8px; border-radius: 4px;">
                             {alert['severity'].upper()}</span></td></tr>
  <tr><td style="padding: 6px; font-weight: bold;">Target</td>
      <td style="padding: 6px; word-break: break-all;"><code>{_escape_html(target)}</code></td></tr>
  <tr><td style="padding: 6px; font-weight: bold;">Time</td>
      <td style="padding: 6px;">{ts}</td></tr>
  <tr><td style="padding: 6px; font-weight: bold;">Tags</td>
      <td style="padding: 6px;">{_escape_html(tags)}</td></tr>
</table>
<h3 style="color: #34495e; margin-top: 16px;">Message</h3>
<p style="background: #f8f9fa; padding: 12px; border-left: 4px solid #3498db; border-radius: 4px;">
{_escape_html(alert['message'])}</p>"""

    if alert.get("data"):
        data_json = json.dumps(alert["data"], indent=2, default=str)
        html_body += f"""<h3 style="color: #34495e;">Extra Data</h3>
<pre style="background: #f0f0f0; padding: 12px; border-radius: 4px; overflow-x: auto;">
{_escape_html(data_json)}</pre>"""

    html_body += f"""<hr style="margin-top: 24px;">
<p style="color: #888; font-size: 12px;">
EdgeIQ Alerting System v{SKILL_VERSION} — generated at {ts}
</p></body></html>"""

    plain_body = (
        f"[{alert.get('source','custom')}] {alert['title']}\n"
        f"{'='*60}\n"
        f"Severity : {alert['severity'].upper()}\n"
        f"Target   : {target}\n"
        f"Time     : {ts}\n"
        f"Tags     : {tags}\n"
        f"\nMessage:\n{alert['message']}\n"
    )
    if alert.get("data"):
        plain_body += f"\nExtra Data:\n{json.dumps(alert['data'], default=str)}\n"

    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.attach(email.mime.text.MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

    return {"from": from_addr, "to": to_addrs, "msg": msg}


# Generic Webhook
def format_webhook(alert: dict, cfg: dict) -> dict:
    webhook_cfg = cfg.get("channels", {}).get("webhook", {})
    secret = webhook_cfg.get("secret", "")
    include_raw = webhook_cfg.get("include_raw_payload", True)

    payload = {
        "alert_id": generate_alert_id(alert),
        "source": alert.get("source", "custom"),
        "severity": alert["severity"],
        "title": alert["title"],
        "message": alert["message"],
        "target": alert.get("target", ""),
        "timestamp": alert.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "tags": alert.get("tags", []),
    }
    if include_raw and alert.get("data"):
        payload["data"] = alert["data"]

    body = json.dumps(payload, default=str)

    headers = {"Content-Type": "application/json"}
    if secret:
        signature = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["X-EdgeIQ-Signature"] = f"sha256={signature}"

    return {"body": body, "headers": headers}


# ---------------------------------------------------------------------------
# Senders
# ---------------------------------------------------------------------------

def send_slack(webhook_url: str, payload: dict) -> tuple[bool, str]:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return True, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)


def send_telegram(bot_token: str, chat_id: str, payload: dict) -> tuple[bool, str]:
    html = payload["html"]
    text = urllib.parse.quote(html, safe="")
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    params = f"chat_id={chat_id}&text={text}&parse_mode=HTML&disable_web_page_preview=true"
    try:
        req = urllib.request.Request(f"{api_url}?{params}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return True, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)


def send_discord(webhook_url: str, payload: dict) -> tuple[bool, str]:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return True, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)


def send_email(cfg: dict, mime_msg) -> tuple[bool, str]:
    email_cfg = cfg.get("channels", {}).get("email", {})
    smtp_host = email_cfg["smtp_host"]
    smtp_port = int(email_cfg.get("smtp_port", 587))
    smtp_user = email_cfg.get("smtp_user", "")
    smtp_pass = email_cfg.get("smtp_pass", "")
    use_tls = email_cfg.get("use_tls", True)

    try:
        if smtp_port == 465:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=20)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)
            server.ehlo()
            if use_tls:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.send_message(mime_msg)
        server.quit()
        return True, "sent"
    except Exception as e:
        return False, str(e)


def send_webhook(cfg: dict, payload: dict) -> tuple[bool, str]:
    webhook_cfg = cfg.get("channels", {}).get("webhook", {})
    url = webhook_cfg["url"]
    try:
        req = urllib.request.Request(
            url,
            data=payload["body"].encode("utf-8"),
            headers=payload["headers"]
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return True, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def route_alert(alert: dict, config: dict, dry_run: bool = False) -> dict:
    """
    Send alert to all configured active channels.
    Returns dict: {channel: (success: bool, message: str, remaining: int|None)}
    """
    channels = config.get("channels", {})
    ratelimit_file = config.get("ratelimit_file", RATE_LIMIT_FILE)
    results = {}

    # --- Slack -----------------------------------------------------------
    slack_cfg = channels.get("slack", {})
    if slack_cfg.get("webhook_url"):
        allowed, remaining = check_rate_limit("slack", config, ratelimit_file)
        if not allowed:
            results["slack"] = (False, "rate limited", None)
        elif dry_run:
            results["slack"] = (True, "dry-run (would send Slack block)", remaining)
        else:
            payload = format_slack(alert)
            ok, msg = send_slack(slack_cfg["webhook_url"], payload)
            results["slack"] = (ok, msg, remaining)

    # --- Telegram -------------------------------------------------------
    tg_cfg = channels.get("telegram", {})
    if tg_cfg.get("bot_token") and tg_cfg.get("chat_id"):
        allowed, remaining = check_rate_limit("telegram", config, ratelimit_file)
        if not allowed:
            results["telegram"] = (False, "rate limited", None)
        elif dry_run:
            results["telegram"] = (True, "dry-run (would send Telegram HTML message)", remaining)
        else:
            payload = format_telegram(alert)
            ok, msg = send_telegram(tg_cfg["bot_token"], tg_cfg["chat_id"], payload)
            results["telegram"] = (ok, msg, remaining)

    # --- Discord --------------------------------------------------------
    discord_cfg = channels.get("discord", {})
    if discord_cfg.get("webhook_url"):
        allowed, remaining = check_rate_limit("discord", config, ratelimit_file)
        if not allowed:
            results["discord"] = (False, "rate limited", None)
        elif dry_run:
            results["discord"] = (True, "dry-run (would send Discord embed)", remaining)
        else:
            payload = format_discord(alert)
            ok, msg = send_discord(discord_cfg["webhook_url"], payload)
            results["discord"] = (ok, msg, remaining)

    # --- Email ----------------------------------------------------------
    email_cfg = channels.get("email", {})
    if email_cfg.get("smtp_host"):
        allowed, remaining = check_rate_limit("email", config, ratelimit_file)
        if not allowed:
            results["email"] = (False, "rate limited", None)
        elif dry_run:
            mime = format_email(alert, config)["msg"]
            results["email"] = (True, f"dry-run (would send email from {mime['From']} to {mime['To']})", remaining)
        else:
            mime = format_email(alert, config)
            ok, msg = send_email(config, mime["msg"])
            results["email"] = (ok, msg, remaining)

    # --- Generic Webhook ------------------------------------------------
    webhook_cfg = channels.get("webhook", {})
    if webhook_cfg.get("url"):
        allowed, remaining = check_rate_limit("webhook", config, ratelimit_file)
        if not allowed:
            results["webhook"] = (False, "rate limited", None)
        elif dry_run:
            results["webhook"] = (True, "dry-run (would POST to webhook)", remaining)
        else:
            payload = format_webhook(alert, config)
            ok, msg = send_webhook(config, payload)
            results["webhook"] = (ok, msg, remaining)

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EdgeIQ Alerting System — route alerts to multiple channels.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 alerter.py --payload \'{"source":"custom","severity":"info","title":"Hi","message":"Test","target":"localhost"}\'
  cat alert.json | python3 alerter.py
  python3 alerter.py --dry-run --payload \'{"source":"custom","severity":"critical","title":"Boom","message":"Explosion","target":"n/a"}\'
        """
    )
    parser.add_argument("--config", "-c", default=DEFAULT_CONFIG,
                        help="Path to config.json (default: config.json)")
    parser.add_argument("--payload", "-p", default=None,
                        help="JSON alert payload as a string argument")
    parser.add_argument("--dry-run", "-n", action="store_true",
                        help="Validate and format but do not send to any channel")
    parser.add_argument("--version", "-v", action="version", version=f"EdgeIQ Alerter v{SKILL_VERSION}")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not os.path.exists(args.config):
        die(f"Config not found: {args.config}  (copy config.json.example and edit it)")

    config = load_config(args.config)

    # --- Load alert payload ---
    if args.payload:
        raw = args.payload.strip()
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        die("No payload provided. Use --payload or pipe JSON via stdin. "
            "Run with --help for usage.")

    try:
        alert = json.loads(raw)
    except json.JSONDecodeError as e:
        die(f"Invalid JSON in payload: {e}")

    if not isinstance(alert, dict):
        die("Payload must be a JSON object (alert dict).")

    # --- Validate ---
    errors = validate_alert(alert)
    if errors:
        for err in errors:
            print(f"VALIDATION ERROR: {err}", file=sys.stderr)
        die("Alert payload validation failed.")

    # --- Normalize timestamp ---
    if not alert.get("timestamp"):
        alert["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    # --- Deduplication check ---
    dedup_file = config.get("dedup_file", DEDUP_FILE)
    c_hash = content_hash(alert)
    if is_duplicate(c_hash, dedup_file):
        print(f"[SKIPPED] Duplicate alert detected (hash: {c_hash[:12]}...). "
              "Skipping send within 5-minute window.", file=sys.stderr)
        sys.exit(0)

    # --- Route ---
    print(f"[EdgeIQ Alerter v{SKILL_VERSION}] Processing alert: [{alert['source']}] "
          f"{alert['severity'].upper()} — {alert['title']}", file=sys.stderr)

    results = route_alert(alert, config, dry_run=args.dry_run)

    # --- Report ---
    any_failure = False
    for channel, (ok, msg, remaining) in sorted(results.items()):
        status = "✅" if ok else "❌"
        rem = f" (remaining: {remaining})" if remaining is not None else ""
        print(f"  {status} {channel}: {msg}{rem}", file=sys.stderr)
        if not ok:
            any_failure = True

    # --- Mark seen on success (not dry-run) ---
    if not args.dry_run:
        mark_seen(c_hash, dedup_file)

    sys.exit(1 if any_failure else 0)


if __name__ == "__main__":
    main()
