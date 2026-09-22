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

_METADATA_WEBHOOK_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)
_OBFUSCATED_IP_LITERAL = re.compile(
    r"^(?:0x[0-9a-f]+|\d{8,}|(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){1,3})$",
    re.IGNORECASE,
)


def _is_canonical_ipv4(hostname: str) -> bool:
    """Return True for a dotted IPv4 address with no leading zeros."""
    parts = hostname.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or (len(part) > 1 and part.startswith("0")) or int(part) > 255:
            return False
    return True


def _is_obfuscated_ip_literal(hostname: str) -> bool:
    """Return True for decimal, hex, octal, or shortened IP literals."""
    if _is_canonical_ipv4(hostname):
        return False
    return _OBFUSCATED_IP_LITERAL.fullmatch(hostname) is not None


class _PinnedWebhookResolver(aiohttp.abc.AbstractResolver):
    """Resolve a webhook host only to addresses that already passed SSRF checks."""

    def __init__(self, hostname: str, addresses: list[str]) -> None:
        self._hostname = hostname.lower().strip("[]")
        self._addresses = list(addresses)

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        requested = host.lower().strip("[]")
        if requested != self._hostname:
            raise OSError("Refusing to resolve an unvalidated webhook host")
        matches: list[dict[str, Any]] = []
        for ip_text in self._addresses:
            parsed_ip = ipaddress.ip_address(ip_text)
            ip_family = socket.AF_INET6 if parsed_ip.version == 6 else socket.AF_INET
            if family not in (socket.AF_UNSPEC, 0, ip_family):
                continue
            matches.append(
                {
                    "hostname": host,
                    "host": ip_text,
                    "port": port,
                    "family": ip_family,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not matches:
            raise OSError("No validated webhook address matches the requested family")
        return matches

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
            self._read_confined_config(config_file, default_config)
        else:
            self._read_confined_config("config/notification_config.json", default_config)

        return default_config

    def _project_root(self) -> Path:
        """Return the repository root that owns this module."""
        return Path(__file__).resolve().parent.parent

    def _config_dir(self) -> Path:
        """Return the notification config directory."""
        return (self._project_root() / "config").resolve()

    def _confine_config_path(self, path: str) -> Path:
        """Resolve a config path and reject anything outside the config directory."""
        root = self._config_dir()
        requested = Path(path)
        if requested.is_absolute():
            resolved = requested.resolve()
        else:
            resolved = (self._project_root() / requested).resolve()
        if not resolved.is_relative_to(root):
            raise ValueError("Notification config path must stay inside the config directory")
        if resolved.suffix.lower() != ".json":
            raise ValueError("Notification config must be a JSON file")
        return resolved

    def _read_confined_config(self, path: str, default_config: dict[str, Any]) -> None:
        """Merge a JSON config file when it stays inside the config directory."""
        try:
            config_path = self._confine_config_path(path)
        except ValueError as exc:
            self.logger.error("Rejected notification config path: %s", exc)
            return
        if not config_path.is_file():
            return
        try:
            with config_path.open(encoding="utf-8") as handle:
                user_config = json.load(handle)
            if not isinstance(user_config, dict):
                raise ValueError("Notification config must be a JSON object")
            self._deep_merge(default_config, user_config)
        except Exception as exc:
            self.logger.error("Failed to load config file %s: %s", path, exc)

    def _confine_attachment(self, attachment_path: str) -> Path | None:
        """Return an attachment path confined to the project tree."""
        root = self._project_root()
        requested = Path(attachment_path)
        if not requested.is_absolute():
            requested = root / requested
        try:
            resolved = requested.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(root):
            self.logger.warning("Rejected attachment outside the project directory")
            return None
        if not resolved.is_file():
            return None
        return resolved

    def _sanitize_header(self, value: str) -> str:
        """Strip CR/LF so notification fields cannot inject extra headers."""
        return str(value).replace("\r", "").replace("\n", "").replace("\x00", "").strip()

    def save_config(self, path: str = "config/notification_config.json") -> None:
        """Persist the current channel configuration to a JSON file.

        Args:
            path: File path to write the configuration to.
        """
        try:
            config_path = self._confine_config_path(path)
        except ValueError as exc:
            self.logger.error("Rejected notification config path: %s", exc)
            raise
        config_path.parent.mkdir(parents=True, exist_ok=True)
        # Only save channel-specific sections (not internal runtime state)
        saveable_keys = [
            "email",
            "slack",
            "discord",
            "webhook",
            "sms",
            "default_channels",
            "rate_limit_per_hour",
        ]
        to_save = {k: self.config[k] for k in saveable_keys if k in self.config}
        try:
            with config_path.open("w", encoding="utf-8") as handle:
                json.dump(to_save, handle, indent=2)
            if os.name != "nt":
                config_path.chmod(0o600)
            self.logger.info(f"Notification config saved to {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to save notification config: {e}")
            raise

    def _allow_private_webhooks(self) -> bool:
        """Whether private network webhook targets are allowed."""
        return os.getenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _blocked_ip_reason(self, ip_text: str, *, allow_private: bool) -> str | None:
        """Return a block reason for addresses that must not receive webhooks."""
        try:
            parsed = ipaddress.ip_address(ip_text)
        except ValueError:
            return "private or restricted"
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return "private or restricted"
        if (
            parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        ):
            return "private or restricted"
        if not allow_private and parsed.is_private:
            return "private or restricted"
        return None

    def _inspect_webhook_url(
        self, url: str, *, allow_private: bool = False
    ) -> tuple[str, list[str]]:
        """Validate a webhook URL and return the URL plus its pinned addresses."""
        cleaned = url.strip()
        try:
            parsed = urlparse(cleaned)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Webhook URL is invalid") from exc
        if parsed.scheme != "https":
            raise ValueError("Webhook URL must use HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Webhook URL must not include credentials")
        if not parsed.hostname or "\\" in parsed.netloc:
            raise ValueError("Webhook URL must include a valid hostname")

        hostname = parsed.hostname.rstrip(".").lower()
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Webhook URL must include a valid hostname") from exc
        if (
            hostname == "localhost"
            or hostname.endswith(".localhost")
            or hostname.endswith(".localhost.localdomain")
        ):
            raise ValueError("Localhost webhook URLs are not allowed")
        if (
            hostname in _METADATA_WEBHOOK_HOSTS
            or hostname.endswith(".metadata.google.internal")
            or hostname.endswith(".metadata.goog")
        ):
            raise ValueError("Webhook URL resolves to a private or restricted network address")
        if _is_obfuscated_ip_literal(hostname):
            raise ValueError("Webhook URL resolves to a private or restricted network address")

        try:
            literal_ip = ipaddress.ip_address(hostname)
        except ValueError:
            literal_ip = None
        if literal_ip is not None:
            reason = self._blocked_ip_reason(str(literal_ip), allow_private=allow_private)
            if reason:
                raise ValueError(f"Webhook URL resolves to a {reason} network address")

        resolved_ips: list[str] = []
        seen: set[str] = set()
        try:
            addrinfo = socket.getaddrinfo(hostname, port or 443, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve webhook hostname: {hostname}") from exc
        for info in addrinfo:
            ip_text = info[4][0]
            if ip_text in seen:
                continue
            seen.add(ip_text)
            reason = self._blocked_ip_reason(ip_text, allow_private=allow_private)
            if reason:
                raise ValueError(f"Webhook URL resolves to a {reason} network address")
            resolved_ips.append(ip_text)
        if not resolved_ips:
            raise ValueError(f"Could not resolve webhook hostname: {hostname}")
        return cleaned, resolved_ips

    def _validate_webhook_url(self, url: str, *, allow_private: bool = False) -> str:
        """Validate outbound webhook URL to reduce SSRF risk."""
        validated, _addresses = self._inspect_webhook_url(url, allow_private=allow_private)
        return validated

    @asynccontextmanager
    async def _pinned_webhook_session(
        self, url: str, *, allow_private: bool
    ) -> AsyncIterator[tuple[str, aiohttp.ClientSession]]:
        """Open an HTTP client pinned to the webhook addresses that were validated."""
        validated, addresses = self._inspect_webhook_url(url, allow_private=allow_private)
        parsed = urlparse(validated)
        resolver = _PinnedWebhookResolver(parsed.hostname or "", addresses)
        connector = aiohttp.TCPConnector(resolver=resolver)
        session = aiohttp.ClientSession(connector=connector, trust_env=False)
        try:
            yield validated, session
        finally:
            await session.close()

    @asynccontextmanager
    async def _open_webhook_response(
        self,
        url: str,
        *,
        allow_private: bool,
        json_body: dict[str, Any],
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> AsyncIterator[aiohttp.ClientResponse]:
        """POST a webhook without redirects, using the pinned validated addresses."""
        async with self._pinned_webhook_session(  # noqa: SIM117
            url, allow_private=allow_private
        ) as (safe_url, session):
            request_kwargs: dict[str, Any] = {"json": json_body, "allow_redirects": False}
            if headers is not None:
                request_kwargs["headers"] = headers
            if timeout is not None:
                request_kwargs["timeout"] = aiohttp.ClientTimeout(total=timeout)
            async with session.post(safe_url, **request_kwargs) as response:
                yield response

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
            msg["From"] = self._sanitize_header(
                email_config.get("from_address", "music-discovery@example.com")
            )
            recipients = [
                self._sanitize_header(recipient)
                for recipient in email_config["recipients"]
                if str(recipient).strip()
            ]
            if not recipients:
                return {"success": False, "error": "Email not configured"}
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = self._sanitize_header(message.title)

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

            # Escape HTML so notification text cannot inject markup.
            safe_html = html.escape(text_content)
            msg.attach(MIMEText(f"<html><body><pre>{safe_html}</pre></body></html>", "html"))

            # Add attachments that stay inside the project tree.
            if message.attachments:
                for attachment_path in message.attachments:
                    safe_path = self._confine_attachment(attachment_path)
                    if safe_path is None:
                        continue
                    with safe_path.open("rb") as handle:
                        attachment = MIMEBase("application", "octet-stream")
                        attachment.set_payload(handle.read())
                        encoders.encode_base64(attachment)
                        attachment.add_header(
                            "Content-Disposition",
                            f"attachment; filename={self._sanitize_header(safe_path.name)}",
                        )
                        msg.attach(attachment)

            # Always verify TLS. Implicit TLS on 465, STARTTLS otherwise.
            tls_context = ssl.create_default_context()
            smtp_host = self._sanitize_header(str(email_config["smtp_server"]))
            smtp_port = int(email_config.get("port", 587))
            if smtp_port == 465:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=tls_context, timeout=30)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.starttls(context=tls_context)

            try:
                if email_config.get("username") and email_config.get("password"):
                    server.login(email_config["username"], email_config["password"])
                server.send_message(msg)
            finally:
                server.quit()

            self.logger.info(
                f"Email notification sent to {len(email_config['recipients'])} recipients"
            )
            return {"success": True, "recipients": len(email_config["recipients"])}

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

            async with self._open_webhook_response(
                webhook_url, allow_private=False, json_body=slack_message
            ) as response:
                if response.status == 200:
                    self.logger.info("Slack notification sent successfully")
                    return {"success": True, "status_code": response.status}
                error_text = await response.text()
                self.logger.error(f"Slack notification failed: {response.status} - {error_text}")
                return {"success": False, "error": f"HTTP {response.status}: {error_text}"}

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

            async with self._open_webhook_response(
                webhook_url, allow_private=False, json_body=discord_message
            ) as response:
                if response.status in [200, 204]:
                    self.logger.info("Discord notification sent successfully")
                    return {"success": True, "status_code": response.status}
                error_text = await response.text()
                self.logger.error(f"Discord notification failed: {response.status} - {error_text}")
                return {"success": False, "error": f"HTTP {response.status}: {error_text}"}

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
            allow_private = self._allow_private_webhooks()
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
            timeout = webhook_config.get("timeout", 30)

            async with self._open_webhook_response(
                url,
                allow_private=allow_private,
                json_body=payload,
                headers=headers,
                timeout=timeout,
            ) as response:
                if 200 <= response.status < 300:
                    self.logger.info(f"Webhook notification sent successfully: {response.status}")
                    return {"success": True, "status_code": response.status}
                error_text = await response.text()
                self.logger.error(f"Webhook notification failed: {response.status} - {error_text}")
                return {"success": False, "error": f"HTTP {response.status}: {error_text}"}

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
