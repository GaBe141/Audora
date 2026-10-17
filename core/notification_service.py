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
import smtplib
import socket
import ssl
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
import jinja2

from core.utils import confine_relative_path, read_nofollow_text, write_private_text


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


class _PinnedResolver:
    """Resolve only the addresses already accepted by webhook validation."""

    def __init__(self, pinned: dict[str, list[str]]) -> None:
        self._pinned = pinned

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        addresses = self._pinned.get(host)
        if not addresses:
            raise OSError(f"Webhook host is not pinned: {host}")
        records: list[dict[str, Any]] = []
        for ip_text in addresses:
            parsed = ipaddress.ip_address(ip_text)
            record_family = socket.AF_INET if parsed.version == 4 else socket.AF_INET6
            if family not in {socket.AF_UNSPEC, record_family}:
                continue
            records.append(
                {
                    "hostname": host,
                    "host": ip_text,
                    "port": port,
                    "family": record_family,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not records:
            raise OSError(f"No pinned address for {host}")
        return records

    async def close(self) -> None:
        """Satisfy the resolver interface without holding sockets."""
        return None


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
        self._pinned_smtp_ips: dict[str, list[str]] = {}

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

        if config_file and Path(config_file).exists():
            try:
                user_config = self._read_config_file(config_file)
                self._deep_merge(default_config, user_config)
            except Exception as e:
                self.logger.error(f"Failed to load config file {config_file}: {e}")

        # Also attempt to load from default config path
        default_path = Path("config/notification_config.json")
        if default_path.exists() and not config_file:
            try:
                user_config = self._read_config_file(default_path)
                self._deep_merge(default_config, user_config)
            except Exception as e:
                self.logger.warning(f"Could not load {default_path}: {e}")

        return default_config

    def _read_config_file(self, path: str | Path) -> dict[str, Any]:
        """Read a notification config without following a symlink."""
        config_path = confine_relative_path(path)
        loaded = json.loads(read_nofollow_text(config_path))
        if not isinstance(loaded, dict):
            raise ValueError("Notification config must be a JSON object")
        return loaded

    def save_config(self, path: str = "config/notification_config.json") -> None:
        """Persist the current channel configuration to a JSON file.

        Args:
            path: Relative file path inside the project root.
        """
        config_path = confine_relative_path(path)
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
            write_private_text(config_path, json.dumps(to_save, indent=2))
            self.logger.info(f"Notification config saved to {config_path}")
        except Exception as e:
            self.logger.error(f"Failed to save notification config: {e}")
            raise

    _CGNAT = ipaddress.ip_network("100.64.0.0/10")
    _SIXTO4_ANYCAST = ipaddress.ip_network("192.88.99.0/24")
    _RFC1918 = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    _NAT64 = ipaddress.ip_network("64:ff9b::/96")
    _NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
    _SIXTO4 = ipaddress.ip_network("2002::/16")
    _TEREDO = ipaddress.ip_network("2001::/32")
    _SITE_LOCAL = ipaddress.ip_network("fec0::/10")
    _AWS_METADATA_V6 = ipaddress.ip_address("fd00:ec2::254")

    def _allow_private_webhooks(self) -> bool:
        """Whether private network webhook targets are allowed."""
        return os.getenv("AUDORA_ALLOW_PRIVATE_WEBHOOKS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _allow_private_smtp(self) -> bool:
        """Whether an RFC1918 SMTP relay is explicitly allowed."""
        return os.getenv("AUDORA_ALLOW_PRIVATE_SMTP", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _unwrap_ip(
        self, parsed: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Return the embedded IPv4 address for an IPv4-mapped IPv6 address."""
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return parsed.ipv4_mapped
        return parsed

    def _in_network(
        self,
        parsed: ipaddress.IPv4Address | ipaddress.IPv6Address,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> bool:
        """Test membership only when the address and network use the same version."""
        if parsed.version != network.version:
            return False
        return parsed in network

    def _is_private_opt_in(self, parsed: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Return True for RFC1918 addresses that may be opted in."""
        unwrapped = self._unwrap_ip(parsed)
        if unwrapped.version != 4:
            return False
        return any(self._in_network(unwrapped, network) for network in self._RFC1918)

    def _is_always_blocked_ip(self, parsed: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Block metadata, loopback, and reserved ranges even when private webhooks are enabled."""
        unwrapped = self._unwrap_ip(parsed)
        if unwrapped.version == 4:
            if self._in_network(unwrapped, self._CGNAT) or self._in_network(
                unwrapped, self._SIXTO4_ANYCAST
            ):
                return True
        elif (
            self._in_network(unwrapped, self._NAT64)
            or self._in_network(unwrapped, self._NAT64_LOCAL)
            or self._in_network(unwrapped, self._SIXTO4)
            or self._in_network(unwrapped, self._TEREDO)
            or self._in_network(unwrapped, self._SITE_LOCAL)
            or unwrapped == self._AWS_METADATA_V6
        ):
            return True

        return bool(
            unwrapped.is_loopback
            or unwrapped.is_link_local
            or unwrapped.is_multicast
            or unwrapped.is_unspecified
            or unwrapped.is_reserved
        )

    def _reject_obfuscated_host(self, hostname: str) -> None:
        """Reject decimal, octal, hex, and short-form numeric hosts before DNS."""
        host = hostname.lower().rstrip(".")
        if host.isdigit():
            raise ValueError("Numeric webhook hosts are not allowed")
        if host.startswith("0x"):
            raise ValueError("Numeric webhook hosts are not allowed")
        labels = host.split(".")
        if labels and all(label.isdigit() for label in labels):
            if len(labels) != 4 or any(
                len(label) > 1 and label.startswith("0") for label in labels
            ):
                raise ValueError("Numeric webhook hosts are not allowed")
            try:
                octets = [int(label) for label in labels]
            except ValueError as exc:
                raise ValueError("Numeric webhook hosts are not allowed") from exc
            if any(octet > 255 for octet in octets):
                raise ValueError("Numeric webhook hosts are not allowed")

    def _assert_ip_allowed(
        self, parsed: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool
    ) -> None:
        """Raise when an address is restricted for outbound webhooks."""
        if self._is_always_blocked_ip(parsed):
            raise ValueError("Webhook URL resolves to a private or restricted network address")
        unwrapped = self._unwrap_ip(parsed)
        if unwrapped.is_private and not (allow_private and self._is_private_opt_in(parsed)):
            raise ValueError("Webhook URL resolves to a private or restricted network address")

    def _assert_smtp_ip(self, parsed: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        """Reject metadata, tunnels, and private relays that were not opted in.

        SMTP sends stored credentials to the pinned address. Teredo stays blocked
        even when RFC1918 relays are enabled because it can encapsulate any IPv4 target.
        """
        if self._is_always_blocked_ip(parsed):
            raise ValueError("SMTP host is restricted")
        unwrapped = self._unwrap_ip(parsed)
        if unwrapped.is_private and not (
            self._allow_private_smtp() and self._is_private_opt_in(parsed)
        ):
            raise ValueError("SMTP host is restricted")

    def _validate_webhook_url(self, url: str, *, allow_private: bool = False) -> str:
        """Validate outbound webhook URL to reduce SSRF risk."""
        parsed = urlparse(url.strip())
        if parsed.scheme != "https":
            raise ValueError("Webhook URL must use HTTPS")
        if parsed.username or parsed.password:
            raise ValueError("Webhook URL must not include userinfo")
        if not parsed.hostname:
            raise ValueError("Webhook URL must include a valid hostname")

        hostname = parsed.hostname
        if hostname.lower().rstrip(".") in {"localhost", "localhost.localdomain"}:
            raise ValueError("Localhost webhook URLs are not allowed")
        self._reject_obfuscated_host(hostname)

        literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None

        resolved_ips: list[str] = []
        if literal is not None:
            self._assert_ip_allowed(literal, allow_private=allow_private)
            resolved_ips.append(str(self._unwrap_ip(literal)))
            if str(literal) not in resolved_ips:
                resolved_ips.append(str(literal))
        else:
            try:
                for info in socket.getaddrinfo(
                    hostname, parsed.port or 443, proto=socket.IPPROTO_TCP
                ):
                    resolved_ips.append(info[4][0])
            except socket.gaierror as e:
                raise ValueError(f"Could not resolve webhook hostname: {hostname}") from e
            if not resolved_ips:
                raise ValueError(f"Could not resolve webhook hostname: {hostname}")
            for ip in resolved_ips:
                try:
                    parsed_ip = ipaddress.ip_address(ip)
                except ValueError as exc:
                    raise ValueError(
                        "Webhook URL resolves to a private or restricted network address"
                    ) from exc
                self._assert_ip_allowed(parsed_ip, allow_private=allow_private)

        self._pinned_webhook_ips = {hostname: resolved_ips}
        return url

    def _validate_smtp_host(self, host: str) -> str:
        """Validate an SMTP hostname and pin the addresses used for the TCP connection.

        The returned hostname is the TLS identity. The connection itself uses the
        pinned addresses so a later DNS change cannot retarget metadata or loopback.
        """
        hostname = host.strip().lower().rstrip(".")
        if not hostname or any(char in hostname for char in "\r\n\t /\\@"):
            raise ValueError("Invalid SMTP host")
        if hostname in {"localhost", "localhost.localdomain"}:
            raise ValueError("Invalid SMTP host")
        self._reject_obfuscated_host(hostname)
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None:
            self._assert_smtp_ip(literal)
            self._pinned_smtp_ips = {hostname: [str(self._unwrap_ip(literal))]}
            return hostname
        try:
            addresses = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ValueError("Invalid SMTP host") from exc
        pinned: list[str] = []
        for info in addresses:
            ip_text = info[4][0]
            try:
                parsed_ip = ipaddress.ip_address(ip_text)
            except ValueError as exc:
                raise ValueError("SMTP host is restricted") from exc
            self._assert_smtp_ip(parsed_ip)
            pin = str(self._unwrap_ip(parsed_ip))
            if pin not in pinned:
                pinned.append(pin)
        if not pinned:
            raise ValueError("Invalid SMTP host")
        self._pinned_smtp_ips = {hostname: pinned}
        return hostname

    def _pinned_smtp_connect_host(self, hostname: str) -> str:
        """Return the address pinned for this SMTP hostname."""
        pinned = self._pinned_smtp_ips.get(hostname)
        if not pinned:
            raise ValueError("SMTP host is not pinned")
        return pinned[0]

    def _safe_header(self, value: str) -> str:
        """Strip CR/LF so header values cannot inject extra headers."""
        return str(value).replace("\r", "").replace("\n", "")

    def _safe_headers(self, headers: dict[str, Any] | None) -> dict[str, str]:
        """Keep only single-line string headers."""
        safe: dict[str, str] = {}
        for key, value in (headers or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                continue
            if any(char in key or char in value for char in "\r\n"):
                continue
            safe[key] = value
        safe.setdefault("Content-Type", "application/json")
        return safe

    def _read_attachment(self, attachment_path: str) -> tuple[str, bytes]:
        """Read an attachment inside the project root without following symlinks."""
        path = confine_relative_path(attachment_path)
        if path.is_symlink():
            raise ValueError("Refusing to attach a symlink")
        fd = -1
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(path, flags)
        try:
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                payload = handle.read()
        finally:
            if fd >= 0:
                os.close(fd)
        filename = self._safe_header(path.name).replace('"', "")
        return filename, payload

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
            msg["From"] = self._safe_header(
                email_config.get("from_address", "music-discovery@example.com")
            )
            msg["To"] = self._safe_header(", ".join(email_config["recipients"]))
            msg["Subject"] = self._safe_header(message.title)

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

            # Add HTML version if available
            html_content = html.escape(text_content).replace("\n", "<br>")
            msg.attach(MIMEText(f"<html><body><pre>{html_content}</pre></body></html>", "html"))

            # Add attachments
            if message.attachments:
                for attachment_path in message.attachments:
                    filename, payload = self._read_attachment(attachment_path)
                    attachment = MIMEBase("application", "octet-stream")
                    attachment.set_payload(payload)
                    encoders.encode_base64(attachment)
                    attachment.add_header(
                        "Content-Disposition",
                        f'attachment; filename="{filename}"',
                    )
                    msg.attach(attachment)

            hostname = self._validate_smtp_host(str(email_config["smtp_server"]))
            connect_host = self._pinned_smtp_connect_host(hostname)
            port = int(email_config.get("port", 587))
            if port not in {465, 587}:
                return {"success": False, "error": "SMTP port must be 465 or 587"}

            tls_context = ssl.create_default_context()
            server: smtplib.SMTP
            if port == 465:
                server = smtplib.SMTP_SSL(timeout=30, context=tls_context)
            else:
                server = smtplib.SMTP(timeout=30)
            # TLS must authenticate the validated name while TCP uses the pinned address.
            server._host = hostname  # type: ignore[attr-defined]
            try:
                server.connect(connect_host, port)
                if port == 587:
                    server.starttls(context=tls_context)
                    server.ehlo()
                if email_config.get("username") and email_config.get("password"):
                    server.login(email_config["username"], email_config["password"])
                server.send_message(msg)
            finally:
                try:
                    server.quit()
                except Exception:
                    server.close()

            self.logger.info(
                f"Email notification sent to {len(email_config['recipients'])} recipients"
            )
            return {"success": True, "recipients": len(email_config["recipients"])}

        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")
            return {"success": False, "error": str(e)}

    async def _post_webhook(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> tuple[int, str]:
        """POST a webhook using the addresses pinned during validation."""
        pinned = getattr(self, "_pinned_webhook_ips", {})
        resolver = _PinnedResolver(pinned)
        connector = aiohttp.TCPConnector(resolver=resolver, ssl=True)  # type: ignore[arg-type]
        client_timeout = aiohttp.ClientTimeout(total=max(1, min(int(timeout), 30)))
        async with (
            aiohttp.ClientSession(connector=connector, trust_env=False) as session,
            session.post(
                url,
                json=payload,
                headers=self._safe_headers(headers),
                timeout=client_timeout,
                allow_redirects=False,
            ) as response,
        ):
            body = await response.text()
            if response.status in {301, 302, 303, 307, 308}:
                raise ValueError("Webhook redirects are not allowed")
            return response.status, body

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
                    if isinstance(value, int | float | str):
                        fields.append(
                            {
                                "title": key.replace("_", " ").title(),
                                "value": str(value),
                                "short": True,
                            }
                        )

                if fields:
                    slack_message["attachments"][0]["fields"] = fields

            status, error_text = await self._post_webhook(webhook_url, slack_message)
            if status == 200:
                self.logger.info("Slack notification sent successfully")
                return {"success": True, "status_code": status}
            self.logger.error(f"Slack notification failed: {status} - {error_text}")
            return {"success": False, "error": f"HTTP {status}: {error_text}"}

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
                    if isinstance(value, int | float | str) and len(fields) < 25:  # Discord limit
                        fields.append(
                            {
                                "name": key.replace("_", " ").title(),
                                "value": str(value)[:1024],  # Discord field limit
                                "inline": True,
                            }
                        )

                if fields:
                    discord_message["embeds"][0]["fields"] = fields

            status, error_text = await self._post_webhook(webhook_url, discord_message)
            if status in {200, 204}:
                self.logger.info("Discord notification sent successfully")
                return {"success": True, "status_code": status}
            self.logger.error(f"Discord notification failed: {status} - {error_text}")
            return {"success": False, "error": f"HTTP {status}: {error_text}"}

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
            url = self._validate_webhook_url(url, allow_private=self._allow_private_webhooks())
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

            status, error_text = await self._post_webhook(
                url, payload, headers=headers, timeout=int(timeout)
            )
            if 200 <= status < 300:
                self.logger.info(f"Webhook notification sent successfully: {status}")
                return {"success": True, "status_code": status}
            self.logger.error(f"Webhook notification failed: {status} - {error_text}")
            return {"success": False, "error": f"HTTP {status}: {error_text}"}

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
