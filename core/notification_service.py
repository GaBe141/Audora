"""
Enhanced notification service for music discovery alerts.
Supports multiple channels, smart filtering, and customizable triggers.
"""

import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import smtplib
import socket
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
import jinja2  # type: ignore[import-untyped]
from aiohttp.abc import AbstractResolver

_LOCAL_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain")
_METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.google.com",
    }
)
_OBFUSCATED_HEX = re.compile(r"0x[0-9a-f]+")
_DOTTED_NUMERIC = re.compile(r"\d+(\.\d+){0,3}")


def _project_root() -> Path:
    """Return the repository root that owns this module."""
    return Path(__file__).resolve().parent.parent


def _safe_header(value: object) -> str:
    """Strip CR/LF so header values cannot inject extra SMTP headers."""
    return str(value).replace("\r", "").replace("\n", "").strip()


def _host_aliases(hostname: str) -> list[str]:
    """Return lowercase host forms a resolver might be asked for."""
    host = hostname.strip().lower().rstrip(".")
    aliases = [host]
    try:
        punycode = host.encode("idna").decode("ascii")
    except UnicodeError:
        punycode = host
    if punycode not in aliases:
        aliases.append(punycode)
    return aliases


def _is_obfuscated_ip_literal(hostname: str) -> bool:
    """Return True for non-canonical numeric hosts such as 2130706433 or 127.1."""
    host = hostname.strip().lower()
    if "%" in host or "/" in host or "@" in host:
        return True
    if _OBFUSCATED_HEX.fullmatch(host) or host.startswith("0x"):
        return True
    if not _DOTTED_NUMERIC.fullmatch(host):
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return True
    for part in parts:
        if len(part) > 1 and part.startswith("0"):
            return True
        if int(part) > 255:
            return True
    return False


class _PinnedResolver(AbstractResolver):
    """Resolve only the addresses chosen during webhook validation."""

    def __init__(self, pinned: dict[str, list[str]]) -> None:
        self._pinned = {host.lower().rstrip("."): list(ips) for host, ips in pinned.items()}

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        ips = self._pinned.get(host.lower().rstrip("."))
        if not ips:
            raise OSError(f"Unpinned webhook host: {host}")
        results: list[dict[str, Any]] = []
        for ip in ips:
            address = ipaddress.ip_address(ip)
            address_family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            if family not in (socket.AF_UNSPEC, address_family):
                continue
            results.append(
                {
                    "hostname": host,
                    "host": ip,
                    "port": port,
                    "family": address_family,
                    "proto": 0,
                    "flags": 0,
                }
            )
        if not results:
            raise OSError(f"No pinned address for {host}")
        return results

    async def close(self) -> None:
        return None


class NotificationPriority(Enum):
    """Notification priority levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationChannel(Enum):
    """Available notification channels."""

    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    WEBHOOK = "webhook"
    CONSOLE = "console"
    SMS = "sms"


@dataclass
class NotificationRule:
    """Notification rule configuration."""

    name: str
    description: str
    conditions: dict[str, Any]
    channels: list[str]
    priority: NotificationPriority
    cooldown_minutes: int = 60
    template: str | None = None
    is_active: bool = True


@dataclass
class NotificationMessage:
    """Notification message structure."""

    title: str
    content: str
    priority: NotificationPriority
    channels: list[NotificationChannel]
    data: dict[str, Any] | None = None
    attachments: list[str] | None = None
    template_vars: dict[str, Any] | None = None


class EnhancedNotificationService:
    """
    Advanced notification system for music discovery events.

    Features:
    - Multiple notification channels
    - Smart filtering and deduplication
    - Template-based messages
    - Rate limiting and cooldown
    - Delivery confirmation
    - Analytics and reporting
    """

    def __init__(self, config_file: str | None = None):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_file)
        self.sent_notifications: dict[str, Any] = {}
        self.notification_history: list[dict[str, Any]] = []
        self.failed_deliveries: list[dict[str, Any]] = []

        # Initialize template engine with autoescape enabled for security
        self.template_env = jinja2.Environment(
            loader=jinja2.DictLoader(self._load_templates()),
            autoescape=jinja2.select_autoescape(
                enabled_extensions=("html", "xml", "jinja2"), default_for_string=True
            ),
        )

        # Channel handlers
        self.channel_handlers = {
            NotificationChannel.EMAIL: self._send_email,
            NotificationChannel.SLACK: self._send_slack,
            NotificationChannel.DISCORD: self._send_discord,
            NotificationChannel.WEBHOOK: self._send_webhook,
            NotificationChannel.CONSOLE: self._send_console,
            NotificationChannel.SMS: self._send_sms,
        }

        # Notification rules
        self.notification_rules = self._load_notification_rules()
        self._pinned_webhook_ips: dict[str, list[str]] = {}

    def _load_config(self, config_file: str | None) -> dict[str, Any]:
        """Load notification configuration."""
        default_config = {
            "enabled": True,
            "default_channels": ["console"],
            "rate_limit_per_hour": 50,
            "batch_notifications": True,
            "batch_delay_minutes": 5,
            "retry_attempts": 3,
            "retry_delay_seconds": 30,
            "email": {
                "smtp_server": os.getenv("SMTP_SERVER", ""),
                "port": int(os.getenv("SMTP_PORT", "587")),
                "username": os.getenv("SMTP_USERNAME", ""),
                "password": os.getenv("SMTP_PASSWORD", ""),
                "from_address": os.getenv("SMTP_FROM", "music-discovery@example.com"),
                "recipients": os.getenv("EMAIL_RECIPIENTS", "").split(","),
                "use_tls": True,
            },
            "slack": {
                "webhook_url": os.getenv("SLACK_WEBHOOK_URL", ""),
                "channel": os.getenv("SLACK_CHANNEL", "#music-trends"),
                "username": os.getenv("SLACK_USERNAME", "Music Discovery Bot"),
                "icon_emoji": ":musical_note:",
            },
            "discord": {
                "webhook_url": os.getenv("DISCORD_WEBHOOK_URL", ""),
                "username": os.getenv("DISCORD_USERNAME", "Music Discovery"),
                "avatar_url": "",
            },
            "webhook": {
                "url": os.getenv("CUSTOM_WEBHOOK_URL", ""),
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {os.getenv('WEBHOOK_TOKEN', '')}",
                },
                "timeout": 30,
            },
            "sms": {
                "provider": "twilio",  # twilio, vonage, etc.
                "api_key": os.getenv("SMS_API_KEY", ""),
                "api_secret": os.getenv("SMS_API_SECRET", ""),
                "from_number": os.getenv("SMS_FROM_NUMBER", ""),
                "recipients": os.getenv("SMS_RECIPIENTS", "").split(","),
            },
        }

        if config_file:
            try:
                config_path = self._confine_project_path(config_file)
                if config_path.is_file():
                    with config_path.open(encoding="utf-8") as f:
                        user_config = json.load(f)
                        self._deep_merge(default_config, user_config)
            except ValueError as e:
                self.logger.error(f"Rejected notification config path: {e}")
            except Exception as e:
                self.logger.error(f"Failed to load config file {config_file}: {e}")

        # Also attempt to load from default config path
        if not config_file:
            try:
                default_path = self._confine_project_path("config/notification_config.json")
                if default_path.is_file():
                    with default_path.open(encoding="utf-8") as f:
                        user_config = json.load(f)
                        self._deep_merge(default_config, user_config)
            except Exception as e:
                self.logger.warning(f"Could not load default notification config: {e}")

        return default_config

    def save_config(self, path: str = "config/notification_config.json") -> None:
        """Persist the current channel configuration to a JSON file.

        Args:
            path: File path to write the configuration to.
        """
        config_path = self._confine_project_path(path)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        # Only save channel-specific sections (not internal runtime state)
        saveable_keys = ["email", "slack", "discord", "webhook", "sms",
                         "default_channels", "rate_limit_per_hour"]
        to_save = {k: self.config[k] for k in saveable_keys if k in self.config}
        try:
            with config_path.open("w") as f:
                json.dump(to_save, f, indent=2)
            if os.name != "nt":
                config_path.chmod(0o600)
            self.logger.info(f"Notification config saved to {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to save notification config: {e}")

    def _confine_project_path(self, path: str) -> Path:
        """Resolve a path and reject targets outside the repository."""
        root = _project_root()
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root):
            raise ValueError("Path must stay inside the project directory")
        return resolved

    def _allow_private_webhooks(self) -> bool:
        """Whether private network webhook targets are allowed."""
        return os.getenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _addresses_for_ip(self, ip: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Return an address plus its IPv4-mapped form when present."""
        try:
            parsed = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return []
        addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [parsed]
        mapped = getattr(parsed, "ipv4_mapped", None)
        if mapped is not None:
            addresses.append(mapped)
        return addresses

    def _is_always_blocked_address(self, ip: str) -> bool:
        """Loopback, link-local, and non-routable addresses stay blocked."""
        addresses = self._addresses_for_ip(ip)
        if not addresses:
            return True
        return any(
            addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            for addr in addresses
        )

    def _is_restricted_ip(self, ip: str, *, allow_private: bool = False) -> bool:
        """Return True when the IP must not be used as a webhook target."""
        if self._is_always_blocked_address(ip):
            return True
        if allow_private:
            return False
        addresses = self._addresses_for_ip(ip)
        if not addresses:
            return True
        return any(addr.is_private or not addr.is_global for addr in addresses)

    def _validate_webhook_url(self, url: str, *, allow_private: bool = False) -> str:
        """Validate an outbound webhook URL and pin the addresses it resolved to."""
        if not isinstance(url, str) or any(char in url for char in "\r\n\t "):
            raise ValueError("Webhook URL contains invalid characters")
        cleaned = url.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme != "https":
            raise ValueError("Webhook URL must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Webhook URL must not include credentials")
        if not parsed.hostname:
            raise ValueError("Webhook URL must include a valid hostname")

        try:
            port = parsed.port or 443
        except ValueError as exc:
            raise ValueError("Webhook URL has an invalid port") from exc

        hostname = parsed.hostname.strip().lower().rstrip(".")
        if hostname in _METADATA_HOSTS or hostname.endswith(".metadata.google.internal"):
            raise ValueError("Metadata webhook hostnames are not allowed")
        if (
            hostname in {"localhost", "localhost.localdomain"}
            or hostname.endswith(_LOCAL_HOST_SUFFIXES)
        ):
            raise ValueError("Localhost webhook URLs are not allowed")
        if "%" in hostname or hostname.startswith("0") and hostname[:2] in {"0x", "00"}:
            raise ValueError("Obfuscated webhook hostnames are not allowed")
        if _is_obfuscated_ip_literal(hostname):
            raise ValueError("Obfuscated IP literals are not allowed")

        literal_addresses = self._addresses_for_ip(hostname)
        if literal_addresses:
            if self._is_restricted_ip(hostname, allow_private=allow_private):
                raise ValueError("Webhook URL resolves to a private or restricted network address")
            pinned = [str(literal_addresses[0])]
            self._pinned_webhook_ips[cleaned] = pinned
            return cleaned

        resolved_ips: list[str] = []
        try:
            infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve webhook hostname: {hostname}") from exc
        for info in infos:
            ip = str(info[4][0]).split("%", 1)[0]
            if self._is_restricted_ip(ip, allow_private=allow_private):
                raise ValueError("Webhook URL resolves to a private or restricted network address")
            if ip not in resolved_ips:
                resolved_ips.append(ip)
        if not resolved_ips:
            raise ValueError(f"Could not resolve webhook hostname: {hostname}")

        self._pinned_webhook_ips[cleaned] = resolved_ips
        return cleaned

    def _sanitize_headers(self, headers: dict[str, Any] | None) -> dict[str, str]:
        """Drop CR/LF from outbound webhook headers."""
        clean: dict[str, str] = {}
        for key, value in (headers or {}).items():
            header_name = _safe_header(key)
            header_value = _safe_header(value)
            if header_name:
                clean[header_name] = header_value
        return clean

    @asynccontextmanager
    async def _webhook_client(self, url: str) -> AsyncIterator[aiohttp.ClientSession]:
        """Open a session that can connect only to the pinned webhook addresses."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        pinned_ips = self._pinned_webhook_ips.get(url)
        if not pinned_ips:
            raise ValueError("Webhook URL was not validated")
        pinned = dict.fromkeys(_host_aliases(hostname), pinned_ips)
        connector = aiohttp.TCPConnector(
            resolver=_PinnedResolver(pinned),
            ssl=ssl.create_default_context(),
            use_dns_cache=False,
        )
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            yield session

    async def _post_webhook(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
    ) -> tuple[int, str]:
        """POST JSON without following redirects or honoring proxy environment variables."""
        bounded_timeout = min(max(float(timeout), 1.0), 30.0)
        client_timeout = aiohttp.ClientTimeout(total=bounded_timeout)
        async with (
            self._webhook_client(url) as session,
            session.post(
                url,
                json=payload,
                headers=self._sanitize_headers(headers),
                allow_redirects=False,
                timeout=client_timeout,
            ) as response,
        ):
            body = await response.text()
            return response.status, body

    def _webhook_http_result(self, status: int, body: str, channel: str) -> dict[str, Any]:
        """Translate a webhook HTTP status into a delivery result."""
        if 300 <= status < 400:
            self.logger.error(f"{channel} notification redirected and was not followed")
            return {"success": False, "error": "Webhook redirects are not allowed"}
        if 200 <= status < 300:
            self.logger.info(f"{channel} notification sent successfully")
            return {"success": True, "status_code": status}
        self.logger.error(f"{channel} notification failed: {status} - {body}")
        return {"success": False, "error": f"HTTP {status}: {body}"}

    def _deep_merge(self, base: dict, update: dict) -> None:
        """Deep merge configuration dictionaries."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _load_templates(self) -> dict[str, str]:
        """Load message templates."""
        return {
            "viral_prediction": """
🔥 VIRAL PREDICTION ALERT 🔥

Track: {{ track_name }} by {{ artist }}
Viral Probability: {{ viral_probability }}%
Confidence: {{ confidence }}%
Predicted Peak: {{ predicted_peak_date }}

Key Factors:
{% for factor in key_factors %}
• {{ factor }}
{% endfor %}

{% if risk_factors %}
Risk Factors:
{% for risk in risk_factors %}
⚠️ {{ risk }}
{% endfor %}
{% endif %}

Act fast - this track is likely to break mainstream soon!
""",
            "trending_daily": """
📈 Daily Trending Report - {{ date }}

Top {{ track_count }} trending tracks:

{% for track in tracks %}
{{ loop.index }}. {{ track.track_name }} by {{ track.artist }}
   Platform: {{ track.platform }} | Score: {{ track.score }}
   {% if track.growth_rate %}Growth: {{ track.growth_rate }}x{% endif %}

{% endfor %}

Cross-platform hits: {{ cross_platform_count }}
New discoveries: {{ new_discoveries }}

View full dashboard: {{ dashboard_url }}
""",
            "breakthrough_alert": """
🚀 BREAKTHROUGH TRACK DETECTED 🚀

{{ track_name }} by {{ artist }} is breaking through!

Current metrics:
• Score: {{ current_score }}
• Growth rate: {{ growth_rate }}x
• Platforms: {{ platform_count }}
• Time to viral: {{ days_to_viral }} days

This track has moved from underground to mainstream trending.
Perfect opportunity for early adoption!
""",
            "cluster_discovery": """
🎵 NEW MUSIC CLUSTER DETECTED 🎵

Cluster: {{ cluster_name }}
Size: {{ cluster_size }} tracks
Average Score: {{ avg_score }}

Key characteristics:
• Energy: {{ energy_level }}
• Danceability: {{ danceability_level }}
• Primary platforms: {{ top_platforms }}

Top artists in cluster:
{% for artist in top_artists %}
• {{ artist.name }} ({{ artist.track_count }} tracks)
{% endfor %}

This represents a new emerging trend worth monitoring!
""",
            "system_alert": """
⚠️ SYSTEM ALERT: {{ alert_type }}

Issue: {{ issue_description }}
Severity: {{ severity }}
Time: {{ timestamp }}

{% if affected_platforms %}
Affected platforms:
{% for platform in affected_platforms %}
• {{ platform }}
{% endfor %}
{% endif %}

{% if resolution_steps %}
Recommended actions:
{% for step in resolution_steps %}
1. {{ step }}
{% endfor %}
{% endif %}

System status: {{ system_status }}
""",
        }

    def _load_notification_rules(self) -> list[NotificationRule]:
        """Load default notification rules."""
        return [
            NotificationRule(
                name="high_viral_prediction",
                description="High confidence viral predictions",
                conditions={"viral_probability": {">=": 0.8}, "confidence": {">=": 0.7}},
                channels=["email", "slack", "discord"],
                priority=NotificationPriority.HIGH,
                cooldown_minutes=30,
                template="viral_prediction",
            ),
            NotificationRule(
                name="daily_trending_summary",
                description="Daily trending tracks summary",
                conditions={"notification_type": "daily_summary"},
                channels=["email", "slack"],
                priority=NotificationPriority.MEDIUM,
                cooldown_minutes=1440,  # Once per day
                template="trending_daily",
            ),
            NotificationRule(
                name="breakthrough_detection",
                description="Underground to mainstream breakthroughs",
                conditions={"breakthrough": True, "score_increase": {">=": 20}},
                channels=["slack", "webhook"],
                priority=NotificationPriority.HIGH,
                cooldown_minutes=60,
                template="breakthrough_alert",
            ),
            NotificationRule(
                name="new_cluster_discovery",
                description="New music trend clusters",
                conditions={"cluster_size": {">=": 10}, "cluster_confidence": {">=": 0.7}},
                channels=["email", "slack"],
                priority=NotificationPriority.MEDIUM,
                cooldown_minutes=360,  # 6 hours
                template="cluster_discovery",
            ),
            NotificationRule(
                name="system_errors",
                description="System errors and alerts",
                conditions={"error_type": "system", "severity": {"in": ["high", "critical"]}},
                channels=["email", "slack", "sms"],
                priority=NotificationPriority.CRITICAL,
                cooldown_minutes=15,
                template="system_alert",
            ),
        ]

    async def send_notification(self, message: NotificationMessage) -> dict[str, Any]:
        """
        Send notification through configured channels.

        Args:
            message: NotificationMessage to send

        Returns:
            Delivery results
        """
        if not self.config.get("enabled", True):
            self.logger.info("Notifications are disabled")
            return {"status": "disabled", "delivered": False}

        # Check rate limiting
        if not self._check_rate_limit():
            self.logger.warning("Rate limit exceeded, skipping notification")
            return {"status": "rate_limited", "delivered": False}

        # Check for duplicates and cooldown
        message_key = self._generate_message_key(message)
        if self._is_in_cooldown(message_key):
            self.logger.info(f"Message in cooldown period: {message_key}")
            return {"status": "cooldown", "delivered": False}

        # Send through each channel
        delivery_results = {}
        successful_channels = []
        failed_channels = []

        for channel in message.channels:
            try:
                if channel in self.channel_handlers:
                    result = await self.channel_handlers[channel](message)
                    delivery_results[channel.value] = result

                    if result.get("success", False):
                        successful_channels.append(channel.value)
                    else:
                        failed_channels.append(channel.value)
                else:
                    self.logger.warning(f"Unknown notification channel: {channel}")
                    failed_channels.append(channel.value)

            except Exception as e:
                self.logger.error(f"Failed to send notification via {channel.value}: {e}")
                delivery_results[channel.value] = {"success": False, "error": str(e)}
                failed_channels.append(channel.value)

        # Record notification
        notification_record = {
            "timestamp": datetime.now().isoformat(),
            "message_key": message_key,
            "title": message.title,
            "priority": message.priority.value,
            "channels_attempted": [c.value for c in message.channels],
            "successful_channels": successful_channels,
            "failed_channels": failed_channels,
            "delivery_results": delivery_results,
        }

        self.notification_history.append(notification_record)

        # Update cooldown tracking
        if successful_channels:
            self.sent_notifications[message_key] = datetime.now()

        # Trim history to prevent memory issues
        if len(self.notification_history) > 1000:
            self.notification_history = self.notification_history[-1000:]

        return {
            "status": "completed",
            "delivered": len(successful_channels) > 0,
            "successful_channels": successful_channels,
            "failed_channels": failed_channels,
            "delivery_results": delivery_results,
        }

    def _check_rate_limit(self) -> bool:
        """Check if rate limit is exceeded."""
        rate_limit = self.config.get("rate_limit_per_hour", 50)
        current_time = datetime.now()
        hour_ago = current_time - timedelta(hours=1)

        # Count notifications in the last hour
        recent_notifications = [
            n
            for n in self.notification_history
            if datetime.fromisoformat(n["timestamp"]) > hour_ago
        ]

        return len(recent_notifications) < rate_limit

    def _generate_message_key(self, message: NotificationMessage) -> str:
        """Generate unique key for message deduplication."""
        # Simple hash based on title and key content
        content_hash = hash(f"{message.title}:{message.content[:100]}")
        return f"{content_hash}:{message.priority.value}"

    def _is_in_cooldown(self, message_key: str, cooldown_minutes: int = 60) -> bool:
        """Check if message is in cooldown period."""
        if message_key not in self.sent_notifications:
            return False

        last_sent = self.sent_notifications[message_key]
        cooldown_period = timedelta(minutes=cooldown_minutes)

        return datetime.now() - last_sent < cooldown_period

    async def _send_email(self, message: NotificationMessage) -> dict[str, Any]:
        """Send notification via email."""
        email_config = self.config.get("email", {})

        if not email_config.get("smtp_server") or not email_config.get("recipients"):
            return {"success": False, "error": "Email not configured"}

        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = _safe_header(
                email_config.get("from_address", "music-discovery@example.com")
            )
            recipients = [
                _safe_header(recipient)
                for recipient in email_config["recipients"]
                if _safe_header(recipient)
            ]
            if not recipients:
                return {"success": False, "error": "Email not configured"}
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = _safe_header(message.title)

            # Set priority
            if message.priority in [NotificationPriority.HIGH, NotificationPriority.CRITICAL]:
                msg["X-Priority"] = (
                    "1" if message.priority == NotificationPriority.CRITICAL else "2"
                )

            # Create text content
            text_content = message.content
            if message.template_vars:
                template = self.template_env.get_template(
                    message.template_vars.get("template", "default")
                )
                text_content = template.render(**message.template_vars)

            msg.attach(MIMEText(text_content, "plain"))

            escaped_html = html.escape(text_content)
            msg.attach(MIMEText(f"<html><body><pre>{escaped_html}</pre></body></html>", "html"))

            # Add attachments confined to the project directory
            if message.attachments:
                for attachment_path in message.attachments:
                    resolved_attachment = self._confine_project_path(str(attachment_path))
                    if not resolved_attachment.is_file():
                        return {"success": False, "error": "Attachment not found"}
                    with resolved_attachment.open("rb") as f:
                        attachment = MIMEBase("application", "octet-stream")
                        attachment.set_payload(f.read())
                        encoders.encode_base64(attachment)
                        attachment.add_header(
                            "Content-Disposition",
                            f"attachment; filename={_safe_header(resolved_attachment.name)}",
                        )
                        msg.attach(attachment)

            smtp_host = _safe_header(email_config.get("smtp_server", ""))
            if not smtp_host or any(char in smtp_host for char in " /\\@"):
                return {"success": False, "error": "Invalid SMTP server"}
            try:
                smtp_port = int(email_config.get("port", 587))
            except (TypeError, ValueError):
                return {"success": False, "error": "Invalid SMTP port"}
            if smtp_port < 1 or smtp_port > 65535:
                return {"success": False, "error": "Invalid SMTP port"}

            tls_context = ssl.create_default_context()
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=tls_context, timeout=30)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.starttls(context=tls_context)

            if email_config.get("username") and email_config.get("password"):
                server.login(email_config["username"], email_config["password"])

            server.send_message(msg)
            server.quit()

            self.logger.info(f"Email notification sent to {len(recipients)} recipients")
            return {"success": True, "recipients": len(recipients)}

        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
            return {"success": False, "error": str(e)}

    async def _send_slack(self, message: NotificationMessage) -> dict[str, Any]:
        """Send notification to Slack."""
        slack_config = self.config.get("slack", {})
        webhook_url = slack_config.get("webhook_url")

        if not webhook_url:
            return {"success": False, "error": "Slack webhook URL not configured"}

        try:
            webhook_url = self._validate_webhook_url(webhook_url, allow_private=False)
            # Create Slack message format
            color_map = {
                NotificationPriority.LOW: "good",
                NotificationPriority.MEDIUM: "warning",
                NotificationPriority.HIGH: "danger",
                NotificationPriority.CRITICAL: "#ff0000",
            }

            # Format content for Slack
            content = message.content
            if message.template_vars:
                template = self.template_env.get_template(
                    message.template_vars.get("template", "default")
                )
                content = template.render(**message.template_vars)

            slack_message = {
                "username": slack_config.get("username", "Music Discovery Bot"),
                "icon_emoji": slack_config.get("icon_emoji", ":musical_note:"),
                "channel": slack_config.get("channel", "#music-trends"),
                "attachments": [
                    {
                        "color": color_map.get(message.priority, "good"),
                        "title": message.title,
                        "text": content,
                        "footer": "Music Discovery System",
                        "ts": int(datetime.now().timestamp()),
                    }
                ],
            }

            # Add fields for structured data
            if message.data:
                fields = []
                for key, value in message.data.items():
                    if isinstance(value, (int, float, str)):
                        fields.append(
                            {
                                "title": key.replace("_", " ").title(),
                                "value": str(value),
                                "short": True,
                            }
                        )

                if fields:
                    slack_message["attachments"][0]["fields"] = fields

            status, body = await self._post_webhook(webhook_url, slack_message)
            return self._webhook_http_result(status, body, "Slack")

        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")
            return {"success": False, "error": str(e)}

    async def _send_discord(self, message: NotificationMessage) -> dict[str, Any]:
        """Send notification to Discord."""
        discord_config = self.config.get("discord", {})
        webhook_url = discord_config.get("webhook_url")

        if not webhook_url:
            return {"success": False, "error": "Discord webhook URL not configured"}

        try:
            webhook_url = self._validate_webhook_url(webhook_url, allow_private=False)
            # Format content for Discord
            content = message.content
            if message.template_vars:
                template = self.template_env.get_template(
                    message.template_vars.get("template", "default")
                )
                content = template.render(**message.template_vars)

            # Discord message format
            discord_message = {
                "username": discord_config.get("username", "Music Discovery"),
                "avatar_url": discord_config.get("avatar_url", ""),
                "embeds": [
                    {
                        "title": message.title,
                        "description": content[:2000],  # Discord limit
                        "color": self._get_priority_color(message.priority),
                        "timestamp": datetime.now().isoformat(),
                        "footer": {"text": "Music Discovery System"},
                    }
                ],
            }

            # Add fields for structured data
            if message.data:
                fields: list[dict[str, Any]] = []
                for key, value in message.data.items():
                    if isinstance(value, (int, float, str)) and len(fields) < 25:  # Discord limit
                        fields.append(
                            {
                                "name": key.replace("_", " ").title(),
                                "value": str(value)[:1024],  # Discord field limit
                                "inline": True,
                            }
                        )

                if fields:
                    discord_message["embeds"][0]["fields"] = fields

            status, body = await self._post_webhook(webhook_url, discord_message)
            return self._webhook_http_result(status, body, "Discord")

        except Exception as e:
            self.logger.error(f"Failed to send Discord notification: {e}")
            return {"success": False, "error": str(e)}

    def _get_priority_color(self, priority: NotificationPriority) -> int:
        """Get Discord embed color based on priority."""
        color_map = {
            NotificationPriority.LOW: 0x00FF00,  # Green
            NotificationPriority.MEDIUM: 0xFFFF00,  # Yellow
            NotificationPriority.HIGH: 0xFF8000,  # Orange
            NotificationPriority.CRITICAL: 0xFF0000,  # Red
        }
        return color_map.get(priority, 0x00FF00)

    async def _send_webhook(self, message: NotificationMessage) -> dict[str, Any]:
        """Send notification to custom webhook."""
        webhook_config = self.config.get("webhook", {})
        url = webhook_config.get("url")

        if not url:
            return {"success": False, "error": "Webhook URL not configured"}

        try:
            url = self._validate_webhook_url(
                url, allow_private=self._allow_private_webhooks()
            )
            # Prepare payload
            payload = {
                "title": message.title,
                "content": message.content,
                "priority": message.priority.value,
                "timestamp": datetime.now().isoformat(),
                "data": message.data or {},
            }

            # Apply template if specified
            if message.template_vars:
                template = self.template_env.get_template(
                    message.template_vars.get("template", "default")
                )
                payload["formatted_content"] = template.render(**message.template_vars)

            headers = webhook_config.get("headers", {"Content-Type": "application/json"})
            try:
                timeout = float(webhook_config.get("timeout", 30))
            except (TypeError, ValueError):
                timeout = 30

            status, body = await self._post_webhook(url, payload, headers=headers, timeout=timeout)
            return self._webhook_http_result(status, body, "Webhook")

        except Exception as e:
            self.logger.error(f"Failed to send webhook notification: {e}")
            return {"success": False, "error": str(e)}

    async def _send_console(self, message: NotificationMessage) -> dict[str, Any]:
        """Send notification to console."""
        try:
            # Format console output
            priority_symbols = {
                NotificationPriority.LOW: "ℹ️",
                NotificationPriority.MEDIUM: "⚠️",
                NotificationPriority.HIGH: "🚨",
                NotificationPriority.CRITICAL: "🔥",
            }

            symbol = priority_symbols.get(message.priority, "📢")

            content = message.content
            if message.template_vars:
                template = self.template_env.get_template(
                    message.template_vars.get("template", "default")
                )
                content = template.render(**message.template_vars)

            print(f"\n{'='*80}")
            print(f"{symbol} {message.title} ({message.priority.value.upper()})")
            print(f"{'='*80}")
            print(content)
            print(f"{'='*80}\n")

            self.logger.info(f"Console notification displayed: {message.title}")
            return {"success": True, "method": "console"}

        except Exception as e:
            self.logger.error(f"Failed to send console notification: {e}")
            return {"success": False, "error": str(e)}

    async def _send_sms(self, message: NotificationMessage) -> dict[str, Any]:
        """Send notification via SMS."""
        sms_config = self.config.get("sms", {})

        if not sms_config.get("api_key") or not sms_config.get("recipients"):
            return {"success": False, "error": "SMS not configured"}

        # For now, return a placeholder (would integrate with actual SMS service)
        self.logger.info("SMS notification would be sent (not implemented)")
        return {"success": True, "method": "sms_placeholder"}

    def get_notification_stats(self, hours: int = 24) -> dict[str, Any]:
        """Get notification statistics for the last N hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)

        recent_notifications = [
            n
            for n in self.notification_history
            if datetime.fromisoformat(n["timestamp"]) > cutoff_time
        ]

        if not recent_notifications:
            return {"message": "No notifications in the specified time period"}

        # Calculate statistics
        total_notifications = len(recent_notifications)
        successful_notifications = len(
            [n for n in recent_notifications if n["successful_channels"]]
        )

        # Channel success rates
        channel_stats: dict[str, dict[str, int | float]] = {}
        for notification in recent_notifications:
            for channel in notification["channels_attempted"]:
                if channel not in channel_stats:
                    channel_stats[channel] = {"attempted": 0, "successful": 0}

                channel_stats[channel]["attempted"] += 1
                if channel in notification["successful_channels"]:
                    channel_stats[channel]["successful"] += 1

        # Calculate success rates
        for _, stats in channel_stats.items():
            stats["success_rate"] = (
                float((stats["successful"] / stats["attempted"]) * 100)
                if stats["attempted"] > 0
                else 0.0
            )

        # Priority distribution
        priority_distribution: dict[str, int] = {}
        for notification in recent_notifications:
            priority = notification["priority"]
            priority_distribution[priority] = priority_distribution.get(priority, 0) + 1

        return {
            "time_period_hours": hours,
            "total_notifications": total_notifications,
            "successful_notifications": successful_notifications,
            "success_rate": (
                (successful_notifications / total_notifications) * 100
                if total_notifications > 0
                else 0
            ),
            "channel_statistics": channel_stats,
            "priority_distribution": priority_distribution,
            "failed_deliveries": len(self.failed_deliveries),
        }


# Example usage and testing
if __name__ == "__main__":
    import asyncio

    async def test_notifications():
        """Test the notification system."""

        # Create notification service
        notifier = EnhancedNotificationService()

        # Test viral prediction notification
        viral_message = NotificationMessage(
            title="🔥 High Viral Potential Detected",
            content="Test track showing strong viral signals",
            priority=NotificationPriority.HIGH,
            channels=[NotificationChannel.CONSOLE, NotificationChannel.SLACK],
            data={
                "track_name": "Test Song",
                "artist": "Test Artist",
                "viral_probability": 85,
                "confidence": 78,
            },
            template_vars={
                "template": "viral_prediction",
                "track_name": "Test Song",
                "artist": "Test Artist",
                "viral_probability": 85,
                "confidence": 78,
                "predicted_peak_date": "2025-10-15",
                "key_factors": ["High growth rate", "Cross-platform presence"],
                "risk_factors": [],
            },
        )

        # Send notification
        result = await notifier.send_notification(viral_message)
        print(f"Notification result: {result}")

        # Test daily summary
        daily_message = NotificationMessage(
            title="📈 Daily Music Trends Summary",
            content="Daily trending tracks report",
            priority=NotificationPriority.MEDIUM,
            channels=[NotificationChannel.CONSOLE],
            template_vars={
                "template": "trending_daily",
                "date": "2025-10-08",
                "track_count": 5,
                "tracks": [
                    {
                        "track_name": "Hit Song 1",
                        "artist": "Artist 1",
                        "platform": "TikTok",
                        "score": 95,
                    },
                    {
                        "track_name": "Hit Song 2",
                        "artist": "Artist 2",
                        "platform": "YouTube",
                        "score": 88,
                    },
                ],
                "cross_platform_count": 3,
                "new_discoveries": 12,
                "dashboard_url": "https://music-dashboard.example.com",
            },
        )

        result = await notifier.send_notification(daily_message)
        print(f"Daily summary result: {result}")

        # Get statistics
        stats = notifier.get_notification_stats(1)  # Last hour
        print(f"Notification stats: {stats}")

    # Run test
    asyncio.run(test_notifications())
