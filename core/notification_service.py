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

_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_DIR = (_PROJECT_ROOT / "config").resolve()
_SMTP_PORTS = frozenset({465, 587})
_LOCAL_SMTP_HOSTS = frozenset({"localhost", "localhost.localdomain"})


class _PinnedResolver(aiohttp.abc.AbstractResolver):
    """Resolve a webhook host only to addresses that already passed SSRF checks."""

    def __init__(self, hostname: str, addresses: list[str]) -> None:
        self._hostname = hostname.lower().rstrip(".")
        self._addresses = addresses

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        requested = host.strip("[]").lower().rstrip(".")
        if requested != self._hostname:
            raise OSError(f"Refusing to resolve unexpected webhook host: {host}")
        results: list[dict[str, Any]] = []
        for ip_text in self._addresses:
            parsed = ipaddress.ip_address(ip_text)
            results.append(
                {
                    "hostname": self._hostname,
                    "host": ip_text,
                    "port": port,
                    "family": socket.AF_INET if parsed.version == 4 else socket.AF_INET6,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not results:
            raise OSError("No pinned addresses for webhook host")
        return results

    async def close(self) -> None:
        return None


class _PinnedSMTP(smtplib.SMTP):
    """SMTP client that dials a previously validated address."""

    def __init__(self, hostname: str, pinned_ip: str, port: int, timeout: int = 30) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(host=hostname, port=port, timeout=timeout)

    def _get_socket(self, host: str, port: int, timeout: float):
        if timeout is not None and not timeout:
            raise ValueError("Non-blocking socket (timeout=0) is not supported")
        return socket.create_connection((self._pinned_ip, port), timeout, self.source_address)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    """SMTPS client that dials a previously validated address and verifies the hostname."""

    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        port: int,
        context: ssl.SSLContext,
        timeout: int = 30,
    ) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(host=hostname, port=port, timeout=timeout, context=context)

    def _get_socket(self, host: str, port: int, timeout: float):
        if timeout is not None and not timeout:
            raise ValueError("Non-blocking socket (timeout=0) is not supported")
        raw = socket.create_connection((self._pinned_ip, port), timeout, self.source_address)
        return self.context.wrap_socket(raw, server_hostname=self._host)


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

        if config_file and Path(config_file).exists():
            try:
                with Path(config_file).open() as f:
                    user_config = json.load(f)
                    # Deep merge configurations
                    self._deep_merge(default_config, user_config)
            except Exception as e:
                self.logger.error(f"Failed to load config file {config_file}: {e}")

        # Also attempt to load from default config path
        default_path = Path("config/notification_config.json")
        if default_path.exists() and not config_file:
            try:
                with default_path.open() as f:
                    user_config = json.load(f)
                    self._deep_merge(default_config, user_config)
            except Exception as e:
                self.logger.warning(f"Could not load {default_path}: {e}")

        return default_config

    def _config_output_path(self, path: str) -> Path:
        """Keep saved notification config inside the project config directory."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = _PROJECT_ROOT / candidate
        resolved = candidate.resolve()
        if resolved.parent != _CONFIG_DIR or resolved.suffix != ".json":
            raise ValueError("Notification config must stay inside the config directory")
        return resolved

    def _redact_secrets(self, value: Any) -> Any:
        """Drop passwords, API secrets, and authorization headers before writing config."""
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for key, item in value.items():
                if str(key).lower() in {"password", "api_key", "api_secret", "authorization"}:
                    continue
                redacted[key] = self._redact_secrets(item)
            return redacted
        if isinstance(value, list):
            return [self._redact_secrets(item) for item in value]
        return value

    def save_config(self, path: str = "config/notification_config.json") -> None:
        """Persist the current channel configuration to a JSON file.

        Args:
            path: File path to write the configuration to.
        """
        config_path = self._config_output_path(path)
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
        to_save = self._redact_secrets(
            {key: self.config[key] for key in saveable_keys if key in self.config}
        )
        try:
            with config_path.open("w") as handle:
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

    def _canonical_ip(self, ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Return the IPv4 address embedded in an IPv4-mapped IPv6 address."""
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError("Webhook URL resolves to an invalid address") from exc
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return parsed.ipv4_mapped
        return parsed

    def _is_always_blocked_ip(self, ip: str) -> bool:
        """Block loopback, link-local metadata, and non-routable targets."""
        parsed = self._canonical_ip(ip)
        return bool(
            parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_unspecified
            or parsed.is_reserved
        )

    def _is_restricted_ip(self, ip: str) -> bool:
        """Return True when the IP belongs to a non-public range."""
        parsed = self._canonical_ip(ip)
        return self._is_always_blocked_ip(ip) or bool(parsed.is_private)

    def _resolve_webhook(self, url: str, *, allow_private: bool = False) -> tuple[str, list[str]]:
        """Validate an outbound webhook URL and return the pinned addresses."""
        parsed = urlparse(url.strip())
        if parsed.scheme != "https":
            raise ValueError("Webhook URL must use HTTPS")
        if parsed.username or parsed.password:
            raise ValueError("Webhook URL must not include credentials")
        if parsed.port not in (None, 443):
            raise ValueError("Webhook URL must use port 443")
        if not parsed.hostname:
            raise ValueError("Webhook URL must include a valid hostname")

        hostname = parsed.hostname.lower().rstrip(".")
        if hostname == "localhost":
            raise ValueError("Localhost webhook URLs are not allowed")

        resolved_ips: list[str] = []
        try:
            for info in socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP):
                address = info[4][0]
                if address not in resolved_ips:
                    resolved_ips.append(address)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve webhook hostname: {hostname}") from exc
        if not resolved_ips:
            raise ValueError(f"Could not resolve webhook hostname: {hostname}")

        for ip in resolved_ips:
            if self._is_always_blocked_ip(ip) or (not allow_private and self._is_restricted_ip(ip)):
                raise ValueError("Webhook URL resolves to a private or restricted network address")

        return url.strip(), resolved_ips

    def _validate_webhook_url(self, url: str, *, allow_private: bool = False) -> str:
        """Validate outbound webhook URL to reduce SSRF risk."""
        validated, _addresses = self._resolve_webhook(url, allow_private=allow_private)
        return validated

    def _validate_smtp_target(self, host: str, port: int) -> str:
        """Return a pinned SMTP address on an allowed submission port."""
        if port not in _SMTP_PORTS:
            raise ValueError("SMTP port must be 465 or 587")
        hostname = host.strip().lower().rstrip(".")
        if not hostname or any(char in hostname for char in " \t\r\n/@\\"):
            raise ValueError("Invalid SMTP server")
        if hostname in _LOCAL_SMTP_HOSTS:
            raise ValueError("Localhost SMTP servers are not allowed")

        resolved_ips: list[str] = []
        try:
            for info in socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP):
                address = info[4][0]
                if address not in resolved_ips:
                    resolved_ips.append(address)
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve SMTP server: {hostname}") from exc

        for ip in resolved_ips:
            parsed = self._canonical_ip(ip)
            if parsed.is_loopback or parsed.is_unspecified:
                raise ValueError("Localhost SMTP servers are not allowed")
            if parsed.is_link_local or parsed.is_multicast or parsed.is_reserved:
                raise ValueError("SMTP server resolves to a restricted network address")
        if not resolved_ips:
            raise ValueError(f"Could not resolve SMTP server: {hostname}")
        return resolved_ips[0]

    def _sanitize_headers(self, headers: dict[str, Any] | None) -> dict[str, str]:
        """Keep webhook headers free of injection and hop-by-hop fields."""
        safe: dict[str, str] = {}
        if isinstance(headers, dict):
            for key, value in headers.items():
                if not isinstance(key, str) or _HEADER_NAME_RE.fullmatch(key) is None:
                    continue
                if key.lower() in {"host", "content-length", "transfer-encoding"}:
                    continue
                if not isinstance(value, str) or any(char in value for char in "\r\n\x00"):
                    continue
                safe[key] = value
        safe["Content-Type"] = "application/json"
        return safe

    def _safe_header_value(self, value: str, label: str) -> str:
        """Reject CR/LF so notification text cannot inject email headers."""
        if any(char in value for char in "\r\n\x00"):
            raise ValueError(f"Email {label} contains forbidden characters")
        return value.strip()

    def _rendered_content(self, message: NotificationMessage) -> str:
        """Render an allowlisted template, or return the plain message content."""
        content = message.content
        if not message.template_vars:
            return content
        template_name = message.template_vars.get("template", "")
        if (
            not isinstance(template_name, str)
            or template_name not in self.template_env.list_templates()
        ):
            return content
        template = self.template_env.get_template(template_name)
        rendered = template.render(**message.template_vars)
        return rendered if isinstance(rendered, str) else content

    def _attachment_path(self, raw_path: str) -> Path | None:
        """Allow attachments only from files inside the project directory."""
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = _PROJECT_ROOT / candidate
        resolved = candidate.resolve()
        if not resolved.is_relative_to(_PROJECT_ROOT.resolve()) or not resolved.is_file():
            self.logger.warning("Skipping attachment outside the project directory")
            return None
        return resolved

    async def _post_json(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        allow_private: bool,
        headers: dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> tuple[int, str]:
        """POST JSON to a pinned HTTPS webhook and do not follow redirects."""
        validated, addresses = self._resolve_webhook(url, allow_private=allow_private)
        parsed = urlparse(validated)
        hostname = parsed.hostname or ""
        resolver = _PinnedResolver(hostname, addresses)
        bounded_timeout = min(max(int(timeout), 1), 30)
        connector = aiohttp.TCPConnector(resolver=resolver, ssl=ssl.create_default_context())
        client_timeout = aiohttp.ClientTimeout(total=bounded_timeout)
        async with (
            aiohttp.ClientSession(connector=connector, trust_env=False) as session,
            session.post(
                validated,
                json=payload,
                headers=self._sanitize_headers(headers),
                timeout=client_timeout,
                allow_redirects=False,
            ) as response,
        ):
            return response.status, await response.text()

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
            smtp_host = str(email_config.get("smtp_server", ""))
            smtp_port = int(email_config.get("port", 587))
            pinned_ip = self._validate_smtp_target(smtp_host, smtp_port)
            recipients = [
                self._safe_header_value(str(recipient), "recipient")
                for recipient in email_config["recipients"]
                if str(recipient).strip()
            ]
            if not recipients:
                return {"success": False, "error": "Email not configured"}

            msg = MIMEMultipart("alternative")
            msg["From"] = self._safe_header_value(
                str(email_config.get("from_address", "music-discovery@example.com")),
                "from address",
            )
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = self._safe_header_value(message.title, "subject")

            # Set priority
            if message.priority in [NotificationPriority.HIGH, NotificationPriority.CRITICAL]:
                msg["X-Priority"] = (
                    "1" if message.priority == NotificationPriority.CRITICAL else "2"
                )

            text_content = self._rendered_content(message)
            msg.attach(MIMEText(text_content, "plain"))

            html_content = html.escape(text_content, quote=True).replace("\n", "<br>")
            msg.attach(MIMEText(f"<html><body><pre>{html_content}</pre></body></html>", "html"))

            if message.attachments:
                for attachment_path in message.attachments:
                    resolved_attachment = self._attachment_path(str(attachment_path))
                    if resolved_attachment is None:
                        continue
                    with resolved_attachment.open("rb") as handle:
                        attachment = MIMEBase("application", "octet-stream")
                        attachment.set_payload(handle.read())
                        encoders.encode_base64(attachment)
                        attachment.add_header(
                            "Content-Disposition",
                            "attachment",
                            filename=resolved_attachment.name.replace('"', ""),
                        )
                        msg.attach(attachment)

            tls_context = ssl.create_default_context()
            if smtp_port == 465:
                server = _PinnedSMTPSSL(smtp_host, pinned_ip, smtp_port, tls_context, timeout=30)
            else:
                server = _PinnedSMTP(smtp_host, pinned_ip, smtp_port, timeout=30)
                server.starttls(context=tls_context)

            if email_config.get("username") and email_config.get("password"):
                server.login(email_config["username"], email_config["password"])

            server.send_message(msg)
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

            content = self._rendered_content(message)

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

            status, error_text = await self._post_json(
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
            content = self._rendered_content(message)

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

            status, error_text = await self._post_json(
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
            payload = {
                "title": message.title,
                "content": message.content,
                "priority": message.priority.value,
                "timestamp": datetime.now().isoformat(),
                "data": message.data or {},
            }
            rendered = self._rendered_content(message)
            if message.template_vars:
                payload["formatted_content"] = rendered

            headers = webhook_config.get("headers", {"Content-Type": "application/json"})
            timeout = webhook_config.get("timeout", 30)
            status, error_text = await self._post_json(
                url,
                payload,
                allow_private=self._allow_private_webhooks(),
                headers=headers if isinstance(headers, dict) else None,
                timeout=int(timeout),
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
