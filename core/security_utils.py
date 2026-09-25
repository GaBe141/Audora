"""Shared guards for outbound requests, exports, and CSV output."""

import ipaddress
import re
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_FORMULA_PREFIXES = ("=", "+", "-", "@")
_LOCALHOST_NAMES = {"localhost", "localhost.localdomain"}
_SUBREDDIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_]{1,20}$")
_TUMBLR_BLOG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?$")
_SNOWFLAKE_RE = re.compile(r"^\d{17,20}$")
_MBID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_COUNTRY_RE = re.compile(r"^(?:global|[a-z]{2})$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_API_PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,240}")
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_IPV4_THIS_HOST = ipaddress.ip_network("0.0.0.0/8")


def neutralize_csv_text(value: Any) -> Any:
    """Prefix spreadsheet formula text so Excel treats it as a literal."""
    if not isinstance(value, str) or value == "":
        return value
    probe = value.lstrip(" \t\r\n")
    if value[:1] in {"\t", "\r", "\n"} or probe[:1] in _FORMULA_PREFIXES:
        return "'" + value
    return value


def neutralize_csv_dataframe(df: Any) -> Any:
    """Neutralize formula prefixes in column names and string cells."""
    if not hasattr(df, "columns") or not hasattr(df, "rename"):
        return df
    renamed = {col: neutralize_csv_text(col) if isinstance(col, str) else col for col in df.columns}
    out = df.rename(columns=renamed).copy()
    for col in out.columns:
        series = out[col]
        dtype_name = str(series.dtype)
        if dtype_name in {"object", "string", "str"} or dtype_name.startswith("string"):
            out[col] = series.map(neutralize_csv_text)
    return out


def confine_project_path(path: str | Path, *, root: Path | None = None) -> Path:
    """Resolve a path and require it to stay inside the project directory."""
    project_root = (root or _PROJECT_ROOT).resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = project_root / candidate
    resolved = candidate.resolve()
    if not resolved.is_relative_to(project_root):
        raise ValueError("Path must stay inside the project directory")
    return resolved


def sanitize_header_value(value: Any) -> str:
    """Remove CR/LF so a value cannot inject extra email or HTTP headers."""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def sanitize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Drop malformed header names and reject header values that contain newlines."""
    clean: dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key)
        if not _HEADER_NAME_RE.fullmatch(name):
            continue
        text = str(value)
        if "\r" in text or "\n" in text or "\x00" in text:
            raise ValueError("Webhook header contains a newline")
        clean[name] = text
    return clean


def ip_policy(ip: str) -> str:
    """Classify an address as public, private, or blocked.

    Loopback, link-local, reserved, multicast, unspecified, and IPv4-mapped
    forms of those ranges are blocked even when private webhooks are allowed.
    """
    try:
        parsed: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(
            ip.split("%", 1)[0]
        )
    except ValueError:
        return "blocked"
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if isinstance(parsed, ipaddress.IPv4Address) and parsed in _IPV4_THIS_HOST:
        return "blocked"
    if (
        parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    ):
        return "blocked"
    if parsed.is_private:
        return "private"
    return "public"


def _resolver_records(hostname: str, port: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve webhook hostname: {hostname}") from exc
    for family, _socktype, proto, _canon, sockaddr in infos:
        ip = str(sockaddr[0]).split("%", 1)[0]
        key = (ip, int(family))
        if key in seen:
            continue
        seen.add(key)
        records.append(
            {
                "hostname": hostname,
                "host": ip,
                "port": port,
                "family": int(family),
                "proto": int(proto),
                "flags": int(socket.AI_NUMERICHOST),
            }
        )
    if not records:
        raise ValueError(f"Could not resolve webhook hostname: {hostname}")
    return records


def validate_https_webhook(
    url: str, *, allow_private: bool = False
) -> tuple[str, str, list[dict[str, Any]]]:
    """Validate a webhook URL and return the URL, hostname, and pinned addresses."""
    if not isinstance(url, str) or "\\" in url or "\n" in url or "\r" in url:
        raise ValueError("Webhook URL must use HTTPS")
    cleaned = url.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme != "https":
        raise ValueError("Webhook URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Webhook URL must not include credentials")
    if parsed.port not in (None, 443):
        raise ValueError("Webhook URL must use port 443")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL must include a valid hostname")
    if hostname.lower().rstrip(".") in _LOCALHOST_NAMES:
        raise ValueError("Localhost webhook URLs are not allowed")

    records = _resolver_records(hostname, 443)
    for record in records:
        policy = ip_policy(str(record["host"]))
        if policy == "blocked" or (policy == "private" and not allow_private):
            raise ValueError("Webhook URL resolves to a private or restricted network address")
    returned = url if url == cleaned else cleaned
    return returned, hostname, records


def validate_smtp_target(host: str, port: int) -> tuple[str, str]:
    """Validate an SMTP server and return the hostname plus the pinned address."""
    if port not in (465, 587):
        raise ValueError("SMTP port must be 465 or 587")
    if not isinstance(host, str) or not host.strip():
        raise ValueError("SMTP server is required")
    hostname = host.strip().rstrip(".")
    if hostname.lower() in _LOCALHOST_NAMES:
        raise ValueError("Localhost SMTP servers are not allowed")
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve SMTP server: {hostname}") from exc
    pinned_ip = ""
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        policy = ip_policy(ip)
        if policy == "blocked":
            address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            if address.is_loopback:
                raise ValueError("Localhost SMTP servers are not allowed")
            raise ValueError("SMTP server resolves to a restricted network address")
        if not pinned_ip:
            pinned_ip = ip
    if not pinned_ip:
        raise ValueError(f"Could not resolve SMTP server: {hostname}")
    return hostname, pinned_ip


class PinnedResolver(aiohttp.abc.AbstractResolver):
    """Resolve only the addresses checked for a webhook hostname."""

    def __init__(self, hostname: str, records: list[dict[str, Any]]) -> None:
        self._hostname = hostname.lower().rstrip(".")
        self._records = records

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        if host.lower().rstrip(".") != self._hostname:
            raise OSError(f"Refusing unpinned host {host}")
        selected: list[dict[str, Any]] = []
        for record in self._records:
            if port and int(record["port"]) != port:
                continue
            if family != socket.AF_UNSPEC and int(record["family"]) != int(family):
                continue
            selected.append(record)
        return selected

    async def close(self) -> None:
        return None


class NoRedirectSession:
    """HTTP session that ignores proxy environment variables and refuses redirects."""

    def __init__(self) -> None:
        self._session = aiohttp.ClientSession(trust_env=False)

    async def __aenter__(self) -> "NoRedirectSession":
        await self._session.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self._session.__aexit__(exc_type, exc, traceback)

    def get(self, url: str, **kwargs: Any) -> Any:
        kwargs["allow_redirects"] = False
        return self._session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        kwargs["allow_redirects"] = False
        return self._session.post(url, **kwargs)


def harden_requests_session(session: Any) -> Any:
    """Stop requests from using HTTP_PROXY or other environment proxies."""
    session.trust_env = False
    return session


def require_safe_api_path(endpoint: str) -> str:
    """Reject path segments that can escape the intended API route."""
    if (
        not isinstance(endpoint, str)
        or not endpoint
        or ".." in endpoint
        or endpoint.startswith(("/", "\\"))
        or "://" in endpoint
        or not _API_PATH_RE.fullmatch(endpoint)
        or any(char in endpoint for char in "?#@\\\r\n\t ")
    ):
        raise ValueError("Unsafe API path")
    return endpoint


def is_subreddit(name: str) -> bool:
    return isinstance(name, str) and _SUBREDDIT_RE.fullmatch(name) is not None


def is_tumblr_blog(name: str) -> bool:
    return isinstance(name, str) and _TUMBLR_BLOG_RE.fullmatch(name) is not None


def is_discord_snowflake(value: str) -> bool:
    return isinstance(value, str) and _SNOWFLAKE_RE.fullmatch(value) is not None


def is_musicbrainz_id(value: str) -> bool:
    return isinstance(value, str) and _MBID_RE.fullmatch(value) is not None


def is_chart_country(value: str) -> bool:
    return isinstance(value, str) and _COUNTRY_RE.fullmatch(value.strip().lower()) is not None


def is_iso_date(value: str) -> bool:
    return isinstance(value, str) and _DATE_RE.fullmatch(value) is not None


def is_audiodb_key(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None
