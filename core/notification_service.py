"""
Enhanced notification service for music discovery alerts.
Supports multiple channels, smart filtering, and customizable triggers.
"""

import asyncio
import html
import ipaddress
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
import jinja2  # type: ignore[import-untyped]

from core.utils import confine_relative_path, read_json, write_json

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_6TO4_ANYCAST = ipaddress.ip_network("192.88.99.0/24")
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_6TO4 = ipaddress.ip_network("2002::/16")
_SITE_LOCAL = ipaddress.ip_network("fec0::/10")
_TEREDO = ipaddress.ip_network("2001::/32")
_IPV4_COMPAT = ipaddress.ip_network("::/96")
_EC2_METADATA_V6 = ipaddress.ip_address("fd00:ec2::254")


def _safe_header(value: str, field: str) -> str:
    """Reject CR, LF, other controls, and DEL so email headers cannot be injected."""
    text = str(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"Invalid characters in email {field}")
    return text


def _safe_attachment_name(name: str) -> str:
    """Return a single attachment filename with no header-breaking characters."""
    filename = Path(name).name
    if filename in {"", ".", ".."} or any(ord(char) < 32 or ord(char) == 127 for char in filename):
        raise ValueError("Invalid attachment filename")
    return filename


def _in_network(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> bool:
    if addr.version != network.version:
        return False
    return addr in network


def _unwrap_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address):
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _is_always_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Block metadata, relay, reserved, and non-routable ranges even when private targets are opted in.

    Python reports deprecated IPv4-compatible addresses (::10.0.0.1, ::127.0.0.1,
    ::169.254.169.254) and other reserved forms such as ::ffff:0:10.0.0.1 as global.
    Those addresses still name restricted targets, so they are never public.
    """
    addr = _unwrap_ip(addr)
    if isinstance(addr, ipaddress.IPv6Address) and _in_network(addr, _IPV4_COMPAT):
        return True
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return True
    if addr.version == 4:
        return _in_network(addr, _CGNAT) or _in_network(addr, _6TO4_ANYCAST)
    return (
        _in_network(addr, _NAT64)
        or _in_network(addr, _NAT64_LOCAL)
        or _in_network(addr, _6TO4)
        or _in_network(addr, _SITE_LOCAL)
        or _in_network(addr, _TEREDO)
        or addr == _EC2_METADATA_V6
    )


def _is_rfc1918(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return addr.version == 4 and any(_in_network(addr, network) for network in _RFC1918)


def _reject_ambiguous_literal(hostname: str, label: str) -> None:
    """Reject decimal, octal, hex, and short IP forms that libc still resolves."""
    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass
    collapsed = hostname.replace(".", "")
    if hostname.lower().startswith("0x") or "0x" in hostname.lower() or collapsed.isdigit():
        raise ValueError(f"{label} must use a canonical hostname or IP address")


class _PinnedResolver:
    """Resolve only the addresses already checked for SSRF."""

    def __init__(self, hostname: str, port: int, ips: list[str]) -> None:
        self.hostname = hostname
        self.port = port
        self.ips = ips

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        if host.strip("[]").rstrip(".").lower() != self.hostname.rstrip(".").lower():
            raise OSError("Refusing to resolve an unexpected webhook host")
        results = []
        for ip in self.ips:
            addr = ipaddress.ip_address(ip)
            fam = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
            if family not in (0, fam):
                continue
            results.append(
                {
                    "hostname": self.hostname,
                    "host": ip,
                    "port": port or self.port,
                    "family": fam,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not results:
            raise OSError("No pinned addresses for the requested family")
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
            self._merge_config_file(default_config, config_file)

        # Also attempt to load from default config path
        if not config_file:
            self._merge_config_file(default_config, "config/notification_config.json")

        return default_config

    def _merge_config_file(self, default_config: dict[str, Any], path: str) -> None:
        """Load a notification config that stays inside the project and is not a symlink."""
        try:
            config_path = confine_relative_path(path)
        except ValueError as exc:
            self.logger.error(f"Rejected notification config path {path}: {exc}")
            return
        if config_path.is_symlink():
            self.logger.error(f"Refusing symlinked notification config: {config_path}")
            return
        if not config_path.is_file():
            return
        try:
            user_config = read_json(config_path)
            if isinstance(user_config, dict):
                self._deep_merge(default_config, user_config)
        except Exception as e:
            self.logger.error(f"Failed to load config file {config_path}: {e}")

    def save_config(self, path: str = "config/notification_config.json") -> None:
        """Persist the current channel configuration to a JSON file.

        Args:
            path: File path to write the configuration to.
        """
        config_path = confine_relative_path(path)
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
            write_json(config_path, to_save)
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

    def _allow_private_smtp(self) -> bool:
        """Whether RFC1918 SMTP servers are explicitly allowed."""
        return os.getenv("AUDORA_ALLOW_PRIVATE_SMTP", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _classify_ip(self, ip: str) -> str:
        """Return public, private, or blocked for an address string."""
        try:
            parsed = _unwrap_ip(ipaddress.ip_address(ip))
        except ValueError:
            return "blocked"
        if _is_always_blocked(parsed):
            return "blocked"
        if parsed.is_private or _is_rfc1918(parsed):
            return "private"
        return "public"

    def _enforce_ip_policy(
        self, ips: set[str] | list[str], *, allow_private: bool, smtp: bool
    ) -> None:
        """Apply webhook or SMTP address policy. Always-blocked ranges ignore the opt-in."""
        label = "SMTP server" if smtp else "Webhook URL"
        for ip in ips:
            kind = self._classify_ip(ip)
            if kind == "public":
                continue
            if kind == "private" and not smtp and allow_private:
                continue
            if (
                kind == "private"
                and smtp
                and allow_private
                and _is_rfc1918(_unwrap_ip(ipaddress.ip_address(ip)))
            ):
                continue
            raise ValueError(f"{label} resolves to a private or restricted network address")

    def _resolve_ips(self, hostname: str, port: int, label: str) -> list[str]:
        """Resolve every address for hostname and reject ambiguous IP literals."""
        _reject_ambiguous_literal(hostname, label)
        resolved: set[str] = set()
        try:
            for info in socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP):
                resolved.add(info[4][0])
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve {label.lower()}: {hostname}") from exc
        if not resolved:
            raise ValueError(f"Could not resolve {label.lower()}: {hostname}")
        return sorted(resolved)

    def _validate_webhook_url(self, url: str, *, allow_private: bool = False) -> str:
        """Validate outbound webhook URL to reduce SSRF risk."""
        self._pin_webhook(url, allow_private=allow_private)
        return url.strip()

    def _pin_webhook(
        self, url: str, *, allow_private: bool = False
    ) -> tuple[str, str, int, list[str]]:
        """Validate a webhook URL and return the hostname plus pinned addresses."""
        cleaned = url.strip()
        if any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in cleaned):
            raise ValueError("Webhook URL contains invalid characters")
        parsed = urlparse(cleaned)
        if parsed.scheme != "https":
            raise ValueError("Webhook URL must use HTTPS")
        if parsed.username or parsed.password:
            raise ValueError("Webhook URL must not include userinfo")
        if not parsed.hostname:
            raise ValueError("Webhook URL must include a valid hostname")

        hostname = parsed.hostname.rstrip(".")
        if hostname.lower() == "localhost":
            raise ValueError("Localhost webhook URLs are not allowed")

        port = parsed.port or 443
        resolved_ips = self._resolve_ips(hostname, port, "Webhook URL")
        self._enforce_ip_policy(resolved_ips, allow_private=allow_private, smtp=False)
        return cleaned, hostname, port, resolved_ips

    def _validate_smtp_host(self, hostname: str) -> tuple[str, list[str]]:
        """Validate an SMTP hostname and return it with the pinned address."""
        cleaned = hostname.strip().rstrip(".")
        if not cleaned or any(ord(char) < 32 or ord(char) == 127 for char in cleaned):
            raise ValueError("SMTP server hostname is invalid")
        if cleaned.lower() == "localhost":
            raise ValueError("Localhost SMTP server is not allowed")
        resolved_ips = self._resolve_ips(cleaned, 0, "SMTP server")
        self._enforce_ip_policy(resolved_ips, allow_private=self._allow_private_smtp(), smtp=True)
        return cleaned, resolved_ips

    def _safe_headers(self, headers: dict[str, Any] | None) -> dict[str, str]:
        """Drop header values that could inject extra header lines."""
        clean: dict[str, str] = {}
        for key, value in (headers or {}).items():
            clean[_safe_header(str(key), "header name")] = _safe_header(str(value), "header value")
        return clean

    async def _post_pinned(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, Any] | None = None,
        timeout: int = 30,
        allow_private: bool = False,
    ) -> tuple[int, str]:
        """POST JSON to a pinned HTTPS endpoint and do not follow redirects."""
        validated, hostname, port, ips = self._pin_webhook(url, allow_private=allow_private)
        resolver = _PinnedResolver(hostname, port, ips)
        connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl.create_default_context())  # type: ignore[arg-type]
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        async with (
            aiohttp.ClientSession(
                connector=connector, trust_env=False, timeout=timeout_cfg
            ) as session,
            session.post(
                validated,
                json=payload,
                headers=self._safe_headers(headers),
                allow_redirects=False,
            ) as response,
        ):
            body = await response.text()
            return response.status, body

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
            recipients = [
                _safe_header(str(recipient).strip(), "recipient")
                for recipient in email_config["recipients"]
                if str(recipient).strip()
            ]
            if not recipients:
                return {"success": False, "error": "Email not configured"}

            msg = MIMEMultipart("alternative")
            msg["From"] = _safe_header(
                email_config.get("from_address", "music-discovery@example.com"), "from"
            )
            msg["To"] = _safe_header(", ".join(recipients), "to")
            msg["Subject"] = _safe_header(message.title, "subject")

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

            # Escape HTML so notification content cannot inject markup.
            html_content = html.escape(text_content).replace("\n", "<br>")
            msg.attach(MIMEText(f"<html><body><pre>{html_content}</pre></body></html>", "html"))

            # Add attachments from inside the project, with header-safe filenames.
            if message.attachments:
                for attachment_path in message.attachments:
                    attachment_file = confine_relative_path(attachment_path)
                    if not attachment_file.is_file():
                        continue
                    safe_name = _safe_attachment_name(attachment_file.name)
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(attachment_file, flags)
                    try:
                        file_obj = os.fdopen(fd, "rb")
                        fd = -1
                        with file_obj:
                            payload = file_obj.read()
                    finally:
                        if fd >= 0:
                            os.close(fd)
                    attachment = MIMEBase("application", "octet-stream")
                    attachment.set_payload(payload)
                    encoders.encode_base64(attachment)
                    attachment.add_header("Content-Disposition", "attachment", filename=safe_name)
                    msg.attach(attachment)

            hostname, pinned_ips = self._validate_smtp_host(str(email_config["smtp_server"]))
            port = int(email_config.get("port", 587))
            if port < 1 or port > 65535:
                raise ValueError("SMTP port is invalid")
            use_tls = bool(email_config.get("use_tls", True))
            if email_config.get("password") and port != 465 and not use_tls:
                return {"success": False, "error": "SMTP password requires TLS"}

            context = ssl.create_default_context()
            server: smtplib.SMTP
            if port == 465:
                server = smtplib.SMTP_SSL(timeout=30, context=context)
            else:
                server = smtplib.SMTP(timeout=30)
            # Certificate checks must use the validated hostname, not the pinned IP.
            server._host = hostname
            try:
                server.connect(pinned_ips[0], port)
                if port != 465 and use_tls:
                    server.starttls(context=context)
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

            status, error_text = await self._post_pinned(
                webhook_url, slack_message, allow_private=False
            )
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

            status, error_text = await self._post_pinned(
                webhook_url, discord_message, allow_private=False
            )
            if status in [200, 204]:
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
            timeout = int(webhook_config.get("timeout", 30))
            status, error_text = await self._post_pinned(
                url,
                payload,
                headers=headers,
                timeout=timeout,
                allow_private=allow_private,
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
