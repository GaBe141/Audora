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
import jinja2  # type: ignore[import-untyped]

from core.utils import open_nofollow, resolve_within_project


class _PinnedAddressResolver(aiohttp.abc.AbstractResolver):
    """Resolve webhook hosts to the addresses already checked for SSRF."""

    def __init__(self, port: int, addresses: tuple[str, ...]) -> None:
        self._port = port
        self._addresses = addresses

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_UNSPEC
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for ip in self._addresses:
            ip_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            if family not in (socket.AF_UNSPEC, ip_family):
                continue
            results.append(
                {
                    "hostname": host,
                    "host": ip,
                    "port": port or self._port,
                    "family": ip_family,
                    "proto": 0,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not results:
            raise OSError(f"No pinned addresses for {host}")
        return results

    async def close(self) -> None:
        return None


class _PinnedSMTP(smtplib.SMTP):
    """SMTP client that connects to a previously validated address."""

    def __init__(self, pinned_ip: str, *args: Any, **kwargs: Any) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return socket.create_connection((self._pinned_ip, port), timeout, self.source_address)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    """SMTPS client that checks the certificate against the original hostname."""

    def __init__(self, pinned_ip: str, *args: Any, **kwargs: Any) -> None:
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        raw = socket.create_connection((self._pinned_ip, port), timeout, self.source_address)
        context = self.context or ssl.create_default_context()
        server_hostname = self._host or host
        return context.wrap_socket(raw, server_hostname=server_hostname)


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
        self._pinned_webhook_targets: dict[str, tuple[str, int, tuple[str, ...]]] = {}
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
            default_path = resolve_within_project("config/notification_config.json")
            if default_path.exists():
                self._merge_config_file(default_config, default_path)

        return default_config

    def _merge_config_file(self, default_config: dict[str, Any], path: str | Path) -> None:
        """Load a config file that stays inside the project and is not a symlink."""
        try:
            config_path = resolve_within_project(path)
            with open_nofollow(config_path, "r") as handle:
                user_config = json.load(handle)
            if isinstance(user_config, dict):
                self._deep_merge(default_config, user_config)
        except FileNotFoundError:
            self.logger.warning(f"Could not load {path}")
        except Exception as e:
            self.logger.error(f"Failed to load config file {path}: {e}")
            raise

    def save_config(self, path: str = "config/notification_config.json") -> None:
        """Persist the current channel configuration to a JSON file.

        Args:
            path: File path to write the configuration to.
        """
        config_path = resolve_within_project(path)
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
            with open_nofollow(config_path, "w") as handle:
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

    def _is_restricted_ip(self, ip: str) -> bool:
        """Return True when the IP belongs to a non-public range."""
        try:
            parsed = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return True
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
        return bool(
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        )

    def _resolve_checked_ips(
        self, hostname: str, port: int, *, allow_private: bool, kind: str
    ) -> tuple[str, ...]:
        """Resolve a host and reject local names, numeric aliases, and restricted addresses."""
        host = hostname.lower().rstrip(".")
        if kind == "webhook" and (
            host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost")
        ):
            raise ValueError("Localhost webhook URLs are not allowed")
        if kind == "smtp" and (
            host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost")
        ):
            raise ValueError("Localhost SMTP servers are not allowed")
        if host.isdigit():
            raise ValueError(f"Numeric {kind} hosts are not allowed")

        resolved_ips: set[str] = set()
        try:
            for info in socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP):
                resolved_ips.add(info[4][0])
        except socket.gaierror as e:
            if kind == "webhook":
                raise ValueError(f"Could not resolve webhook hostname: {hostname}") from e
            raise ValueError(f"Could not resolve SMTP hostname: {hostname}") from e

        if not resolved_ips:
            raise ValueError(f"Could not resolve {kind} hostname: {hostname}")

        if not allow_private:
            for ip in resolved_ips:
                if self._is_restricted_ip(ip):
                    if kind == "webhook":
                        raise ValueError(
                            "Webhook URL resolves to a private or restricted network address"
                        )
                    raise ValueError(
                        "SMTP server resolves to a private or restricted network address"
                    )

        return tuple(sorted(resolved_ips))

    def _validate_webhook_url(self, url: str, *, allow_private: bool = False) -> str:
        """Validate an outbound webhook URL and pin the addresses it resolved to."""
        if not isinstance(url, str) or any(char in url for char in "\r\n\t\\"):
            raise ValueError("Webhook URL must use HTTPS")
        normalized = url.strip()
        parsed = urlparse(normalized)
        if parsed.scheme != "https":
            raise ValueError("Webhook URL must use HTTPS")
        if parsed.username or parsed.password:
            raise ValueError("Webhook URL must not include credentials")
        if not parsed.hostname:
            raise ValueError("Webhook URL must include a valid hostname")

        hostname = parsed.hostname
        port = parsed.port or 443
        resolved_ips = self._resolve_checked_ips(
            hostname, port, allow_private=allow_private, kind="webhook"
        )
        self._pinned_webhook_targets[normalized] = (hostname, port, resolved_ips)
        return normalized

    def _validate_smtp_host(
        self, host: str, *, allow_private: bool | None = None
    ) -> tuple[str, tuple[str, ...]]:
        """Validate an SMTP hostname and return the addresses it may connect to."""
        if allow_private is None:
            allow_private = os.getenv("AUDORA_ALLOW_PRIVATE_SMTP", "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
        if not isinstance(host, str):
            raise ValueError("Invalid SMTP host")
        hostname = host.strip()
        if not hostname or any(char in hostname for char in "\r\n\t /\\@"):
            raise ValueError("Invalid SMTP host")
        resolved_ips = self._resolve_checked_ips(
            hostname, 587, allow_private=allow_private, kind="smtp"
        )
        return hostname, resolved_ips

    def _sanitize_webhook_headers(self, headers: Any) -> dict[str, str]:
        """Drop header names that can retarget the request or inject extra headers."""
        safe: dict[str, str] = {}
        if isinstance(headers, dict):
            for key, value in headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    continue
                if any(char in key or char in value for char in "\r\n\0"):
                    continue
                lowered = key.lower().strip()
                if lowered in {"host", "content-length", "transfer-encoding", "connection"}:
                    continue
                if lowered not in {
                    "content-type",
                    "authorization",
                    "user-agent",
                } and not lowered.startswith("x-"):
                    continue
                safe[key.strip()] = value.strip()
        safe.setdefault("Content-Type", "application/json")
        return safe

    def _single_line(self, value: str, label: str) -> str:
        """Reject CR/LF so email headers cannot be injected."""
        if not isinstance(value, str) or any(char in value for char in "\r\n"):
            raise ValueError(f"Invalid email {label}")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"Invalid email {label}")
        return cleaned

    async def _post_webhook_json(
        self,
        url: str,
        payload: dict[str, Any],
        headers: Any,
        timeout: Any,
    ) -> tuple[int, str]:
        """POST JSON without redirects, proxies, or a second DNS lookup."""
        pinned = self._pinned_webhook_targets.get(url)
        if pinned is None:
            raise ValueError("Webhook URL was not validated")
        _hostname, port, addresses = pinned
        try:
            timeout_seconds = max(1, min(int(timeout), 30))
        except (TypeError, ValueError):
            timeout_seconds = 30
        resolver = _PinnedAddressResolver(port, addresses)
        connector = aiohttp.TCPConnector(resolver=resolver, ssl=True)
        client_timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with (
            aiohttp.ClientSession(connector=connector, trust_env=False) as session,
            session.post(
                url,
                json=payload,
                headers=self._sanitize_webhook_headers(headers),
                timeout=client_timeout,
                allow_redirects=False,
            ) as response,
        ):
            body = await response.text()
            return response.status, body[:2000]

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
            hostname, pinned_ips = self._validate_smtp_host(
                str(email_config.get("smtp_server", ""))
            )
            try:
                port = int(email_config.get("port", 587))
            except (TypeError, ValueError) as e:
                raise ValueError("Invalid SMTP port") from e
            if port not in {465, 587}:
                raise ValueError("SMTP port must be 465 or 587")

            recipients = email_config.get("recipients") or []
            if isinstance(recipients, str):
                recipients = [recipients]
            safe_recipients = [
                self._single_line(str(item), "recipient")
                for item in recipients
                if str(item).strip()
            ]
            if not safe_recipients or any("@" not in item for item in safe_recipients):
                raise ValueError("Invalid email recipient")

            msg = MIMEMultipart("alternative")
            msg["From"] = self._single_line(
                str(email_config.get("from_address", "music-discovery@example.com")), "from address"
            )
            msg["To"] = ", ".join(safe_recipients)
            msg["Subject"] = self._single_line(message.title, "subject")

            # Set priority
            if message.priority in [NotificationPriority.HIGH, NotificationPriority.CRITICAL]:
                msg["X-Priority"] = (
                    "1" if message.priority == NotificationPriority.CRITICAL else "2"
                )

            # Create text content
            text_content = message.content
            if message.template_vars:
                template_name = str(message.template_vars.get("template", "default"))
                if template_name not in self.template_env.list_templates():
                    raise ValueError("Unknown notification template")
                template = self.template_env.get_template(template_name)
                text_content = template.render(**message.template_vars)

            msg.attach(MIMEText(text_content, "plain"))

            # Escape HTML so notification text cannot inject markup.
            html_content = html.escape(text_content).replace("\n", "<br>")
            msg.attach(MIMEText(f"<html><body><pre>{html_content}</pre></body></html>", "html"))

            # Add attachments from inside the project only.
            if message.attachments:
                for attachment_path in message.attachments:
                    attachment_file = resolve_within_project(attachment_path)
                    if not attachment_file.is_file():
                        raise ValueError("Attachment is not a regular file")
                    with open_nofollow(attachment_file, "rb") as handle:
                        payload = handle.read(5_000_000)
                    attachment = MIMEBase("application", "octet-stream")
                    attachment.set_payload(payload)
                    encoders.encode_base64(attachment)
                    attachment.add_header(
                        "Content-Disposition",
                        f'attachment; filename="{attachment_file.name}"',
                    )
                    msg.attach(attachment)

            # TLS is mandatory. Connect to the pinned address and verify the hostname.
            context = ssl.create_default_context()
            pinned_ip = pinned_ips[0]
            if port == 465:
                server = _PinnedSMTPSSL(pinned_ip, context=context, timeout=30)
            else:
                server = _PinnedSMTP(pinned_ip, timeout=30)
            server.connect(hostname, port)
            server.ehlo()
            if port != 465:
                server.starttls(context=context)
                server.ehlo()

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

            status, error_text = await self._post_webhook_json(webhook_url, slack_message, None, 30)
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

            status, error_text = await self._post_webhook_json(
                webhook_url, discord_message, None, 30
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

            status, error_text = await self._post_webhook_json(url, payload, headers, timeout)
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
