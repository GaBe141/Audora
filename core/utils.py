"""Shared utility functions for the Audora project."""

import errno
import io
import json
import logging
import os
import re
import stat
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_CSV_FORMULA_STARTS = ("=", "+", "-", "@")
_SECRET_FILE_NAMES = {
    ".env",
    ".cache",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".envrc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "credentials.json",
    "credentials",
    ".pgpass",
    ".my.cnf",
    ".htpasswd",
    ".boto",
    ".s3cfg",
    "authorized_keys",
    "authorized_keys2",
    "notification_config.json",
    "enhanced_api_config.json",
    "social_apis.json",
}
_LIVE_CONFIG_NAMES = {
    "notification_config.json",
    "enhanced_api_config.json",
    "social_apis.json",
}
_SECRET_FILE_SUFFIXES = (
    ".db",
    ".sqlite",
    ".sqlite3",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    ".sqlite-wal",
    ".sqlite-shm",
    ".sqlite-journal",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".ppk",
    ".kdbx",
    ".p8",
    ".tfstate",
)
_DISGUISED_FILE_SUFFIXES = (
    ".backup",
    ".disabled",
    ".orig",
    ".save",
    ".copy",
    ".bkp",
    ".bck",
    ".bak",
    ".old",
    ".swn",
    ".swo",
    ".swp",
    ".swx",
    ".tmp",
    ".new",
    "~",
)
_NUMERIC_COPY_RE = re.compile(r"(.+)\.(\d+)$")
# FAT illegal-character bitmap from RtlGenerate8dot3Name. Bit set means the
# ASCII character cannot appear in an 8.3 name and is rewritten to "_".
_FAT_ILLEGAL_BITS = (0xFFFFFFFF, 0xFC009C04, 0x38000000, 0x10000000)
_ENV_SHORT_BASES = frozenset({"env", "envrc"})
_ENV_SHORT_SUFFIXES = (
    "local",
    "development",
    "production",
    "prod",
    "test",
    "staging",
    "example",
    "preview",
    "dev",
    "qa",
    "ci",
)
# First three characters of sensitive extensions that do not fit in 8.3,
# plus the FsRtlSafeExtensions form that rewrites the third character to "~".
_TRUNCATED_SECRET_EXTENSIONS = frozenset({"sql", "sq~", "kdb", "kd~", "tfs", "tf~", "db-", "db~"})
_GENERATED_SHORT_NAME_RE = re.compile(
    r"^([a-z0-9_$%'@`!(){}^#&\-]{1,6})~(\d{1,6})"
    r"(?:\.([a-z0-9_$%'@`!(){}^#&\-]{0,2}~?|[a-z0-9_$%'@`!(){}^#&\-]{1,3}))?$"
)
# Collision form: the first two basis characters plus four checksum nibbles.
# ``.env.canary.local`` is ``ENVCAN~1.LOC`` until names collide, then
# ``EN9DD6~1.LOC``. The third character is a hex digit, so this does not match
# the primary basis ``ENVCAN`` or ``ENVIRO``.
_DOTENV_CHECKSUM_BASIS_RE = re.compile(r"^en[0-9a-f]{4}$")
# ``.env.<mode>`` stores the mode in the extension (``.env.canary`` →
# ``ENB38A~1.CAN``). Ordinary files that share the ``EN`` + checksum shape
# keep ``txt`` and ``csv``. The safe-extension form rewrites the third
# character to ``~`` (``TX~``), and filename normalization then strips that
# trailing tilde, so ``tx`` and ``cs`` are the same document extensions.
_BENIGN_CHECKSUM_EXTENSIONS = frozenset({"txt", "csv", "tx~", "cs~", "tx", "cs"})

# Re-export for convenience
try:
    import pandas as pd

    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


def _is_fat_illegal(char: str) -> bool:
    """True when an ASCII character is illegal in a Windows 8.3 name."""
    code = ord(char)
    if code >= 128:
        return True
    return bool(_FAT_ILLEGAL_BITS[code // 32] & (1 << (code % 32)))


def _lfn_checksum(name: str) -> int:
    """Windows long-name checksum used once several 8.3 aliases collide."""
    chars = [ord(char) for char in name]
    if not chars:
        return 0
    if len(chars) == 1:
        return chars[0] & 0xFFFF
    checksum = ((chars[0] << 8) + chars[1]) & 0xFFFF
    index = 2
    while index < len(chars):
        checksum = (
            (0x8000 if checksum & 1 else 0) + (checksum >> 1) + (chars[index] << 8)
        ) & 0xFFFF
        if index + 1 < len(chars):
            checksum = (checksum + chars[index + 1]) & 0xFFFF
        index += 2
    return checksum


def _checksum_digits(name: str) -> str:
    """Four checksum nibbles, least significant nibble first, as Windows emits them."""
    checksum = _lfn_checksum(name)
    digits: list[str] = []
    for _ in range(4):
        nibble = checksum & 0xF
        if nibble <= 9:
            digits.append(chr(ord("0") + nibble))
        else:
            digits.append(chr(ord("A") + nibble - 10))
        checksum >>= 4
    return "".join(digits)


def _next_short_char(name: str, index: int, *, skip_dots: bool) -> tuple[str, int]:
    """Return the next 8.3 basis character and the index after it."""
    while index < len(name):
        char = name[index]
        index += 1
        if char <= " " or ord(char) >= 127 or (char == "." and skip_dots):
            continue
        if _is_fat_illegal(char):
            char = "_"
        elif "a" <= char <= "z":
            char = chr(ord(char) - 32)
        return char, index
    return "", index


def _short_name_parts(name: str) -> tuple[str, str, bool, bool]:
    """Return basis, extension, whether the extension was truncated, and early checksum.

    This follows the ASCII path of ``RtlGenerate8dot3Name``: skip a leading dot,
    keep the last dot as the extension separator, and insert a checksum when the
    basis is two characters or shorter.
    """
    index = 0
    skip_dots = name.startswith(".")
    last_dot_index: int | None = None
    while True:
        char, index = _next_short_char(name, index, skip_dots=skip_dots)
        skip_dots = False
        if not char:
            break
        if char == ".":
            last_dot_index = index
    if last_dot_index == len(name):
        last_dot_index = None

    basis_chars: list[str] = []
    index = 0
    while len(basis_chars) < 6:
        char, next_index = _next_short_char(name, index, skip_dots=True)
        if not char or (last_dot_index is not None and next_index >= last_dot_index):
            break
        basis_chars.append(char)
        index = next_index

    early_checksum = len(basis_chars) <= 2
    if early_checksum:
        basis_chars.extend(_checksum_digits(name))

    extension_chars: list[str] = []
    truncated = False
    if last_dot_index is not None:
        scan = last_dot_index
        while len(extension_chars) < 3:
            char, scan = _next_short_char(name, scan, skip_dots=True)
            if not char:
                break
            extension_chars.append(char)
        extra, _scan = _next_short_char(name, scan, skip_dots=True)
        truncated = bool(extra)
    return "".join(basis_chars), "".join(extension_chars), truncated, early_checksum


def _dotenv_document_checksums() -> frozenset[str]:
    """Collision bases of dotenv files whose extension is ``txt`` or ``csv``.

    ``.env.txt`` is ``EN8119~1.TXT``. That extension is shared with
    ``environment.txt`` (``EN41DD~1.TXT``), so the extension allowlist cannot
    refuse it. The bases are derived from the long names.
    """
    names: list[str] = []
    for stem in (".env", ".envrc"):
        for extension in ("txt", "csv"):
            names.append(f"{stem}.{extension}")
            names.append(f"{stem}.{extension}~")
    bases: set[str] = set()
    for name in names:
        basis, _extension, _truncated, early_checksum = _short_name_parts(name)
        if not basis or early_checksum:
            continue
        bases.add((basis[:2] + _checksum_digits(name)).casefold())
    return frozenset(bases)


_DOTENV_DOCUMENT_CHECKSUMS = _dotenv_document_checksums()


def _tilde_aliases(basis: str, extension: str) -> set[str]:
    """``~1`` through ``~9`` spellings of one 8.3 basis."""
    if not basis:
        return set()
    suffix = f".{extension}" if extension else ""
    return {f"{basis}~{number}{suffix}".casefold() for number in range(1, 10)}


def _windows_short_aliases(name: str) -> set[str]:
    """8.3 aliases Windows may store for ``name``, including safe-extension forms."""
    basis, extension, truncated, early_checksum = _short_name_parts(name)
    extensions = [extension]
    if truncated and extension:
        extensions.append(f"{extension[:-1]}~")
    bases = [basis]
    if basis and not early_checksum:
        bases.append(basis[:2] + _checksum_digits(name))
    aliases: set[str] = set()
    for short_basis in bases:
        for short_extension in extensions:
            aliases.update(_tilde_aliases(short_basis, short_extension))
    return aliases


def _dotenv_compound_extensions() -> frozenset[str]:
    """8.3 extensions of ``.local`` and of backup or numbered copies of that name.

    ``.env.production.local`` keeps the mode in the basis (``ENVPRO``) and puts
    ``local`` in the extension (``LOC``). A backup such as
    ``.env.production.local.bak`` moves the disguise into that extension.
    """
    tails = [".local"]
    for extra in _DISGUISED_FILE_SUFFIXES:
        if extra == "~":
            continue
        tails.append(f".local{extra}")
        tails.append(extra)
    tails.extend(f".local.{number}" for number in range(1, 10))
    tails.extend(f".{number}" for number in range(1, 10))
    found: set[str] = set()
    for tail in tails:
        _basis, extension, truncated, _early = _short_name_parts(f"name{tail}")
        if not extension:
            continue
        found.add(extension.casefold())
        if truncated:
            found.add(f"{extension[:-1]}~".casefold())
    return frozenset(found)


_DOTENV_COMPOUND_EXTENSIONS = _dotenv_compound_extensions()


def _sensitive_long_names() -> set[str]:
    """Long names whose generated 8.3 aliases must be treated as secret."""
    names = set(_SECRET_FILE_NAMES)
    for suffix in _ENV_SHORT_SUFFIXES:
        names.add(f".env.{suffix}")
        names.add(f".envrc.{suffix}")
        # Next.js, Vite, and dotenv load ``.env.<mode>.local`` after ``.env.<mode>``.
        # The extra segment lengthens the 8.3 basis past ``ENV``, so the env/envrc
        # basis check does not see ``ENVPRO~1.LOC``.
        names.add(f".env.{suffix}.local")
        names.add(f".envrc.{suffix}.local")
    expanded = set(names)
    for name in names:
        for extra in _DISGUISED_FILE_SUFFIXES:
            expanded.add(f"{name}{extra}")
        for number in range(1, 10):
            expanded.add(f"{name}.{number}")
        expanded.add(f".{name}")
        expanded.add(f"#{name}#")
        expanded.add(f".#{name}")
        for swap in (".swp", ".swo", ".swn", ".swx"):
            expanded.add(f".{name}{swap}")
    return expanded


def _short_secret_aliases() -> frozenset[str]:
    aliases: set[str] = set()
    for name in _sensitive_long_names():
        aliases.update(_windows_short_aliases(name))
    return frozenset(aliases)


_SHORT_SECRET_ALIASES = _short_secret_aliases()


def _is_windows_short_secret(candidate: str) -> bool:
    """True when ``candidate`` is a Windows 8.3 alias of a secret or database.

    NTFS can store ``ENV~1`` for ``.env`` and ``CREDEN~1.JSO`` for
    ``credentials.json``. ``.env.production.local`` is ``ENVPRO~1.LOC``: the
    mode sits in the basis, so an ``ENV`` / ``ENVRC`` basis check misses it.
    After collisions the same file is ``EN9DD6~1.LOC`` (``EN`` plus the
    long-name checksum). Generation is often disabled on current volumes; when
    a short name exists, opening it still opens the long file.
    """
    if candidate in _SHORT_SECRET_ALIASES:
        return True
    match = _GENERATED_SHORT_NAME_RE.fullmatch(candidate)
    if match is None:
        return False
    basis = match.group(1)
    extension = match.group(3) or ""
    if extension in _TRUNCATED_SECRET_EXTENSIONS:
        return True
    if basis in _ENV_SHORT_BASES:
        return True
    # Any ``.env.<mode>.local`` (and its backup or numbered copy) starts the
    # basis with ENV and puts ``local`` or the disguise in the extension.
    # ``environment.txt`` is ``ENVIRO~1.TXT`` and stays allowed. ``ENVPRO~1``
    # with no extension is the short name of ``envprofile`` and stays allowed.
    if basis.startswith("env") and extension in _DOTENV_COMPOUND_EXTENSIONS:
        return True
    # Unlisted modes are not in ``_SHORT_SECRET_ALIASES``. After collisions
    # ``.env.<mode>`` and ``.envrc.<mode>`` keep only ``EN`` plus the checksum
    # and put the mode in the extension (``.env.canary`` → ``ENB38A~1.CAN`` /
    # ``ENB38A~1.CA~``). ``txt`` and ``csv`` stay allowed so ``EN41DD~1.TXT``
    # (``environment.txt``) and ``EN0EED~1.CSV`` (``envelope.csv``) still open.
    # ``ENA51B~1`` (``envprofile``) has no extension. ``.env.txt`` uses the
    # same extension with a different checksum and is refused by basis.
    if _DOTENV_CHECKSUM_BASIS_RE.fullmatch(basis) is None or not extension:
        return False
    if basis in _DOTENV_DOCUMENT_CHECKSUMS:
        return True
    return extension not in _BENIGN_CHECKSUM_EXTENSIONS


def _filename_forms(filename: str) -> list[str]:
    """Spellings that still name the same file on Windows and case-insensitive disks.

    Trailing dots and spaces, NTFS alternate data streams, editor backups, and
    numbered copies are removed one layer at a time. ``id_rsa.bak.`` and
    ``id_rsa::$DATA`` both reduce to ``id_rsa``. ``credentials.json.backup``
    and ``id_rsa.2`` reduce to the secret base name.
    """
    name = filename.casefold().strip()
    forms: list[str] = []
    seen: set[str] = set()
    while name and name not in seen:
        seen.add(name)
        forms.append(name)
        trimmed = name.rstrip(". ")
        if trimmed != name:
            name = trimmed
            continue
        stream, separator, _rest = name.partition(":")
        if separator and stream:
            name = stream
            continue
        peeled = False
        for extra in _DISGUISED_FILE_SUFFIXES:
            if name.endswith(extra) and len(name) > len(extra):
                name = name[: -len(extra)]
                peeled = True
                break
        if peeled:
            continue
        numeric = _NUMERIC_COPY_RE.fullmatch(name)
        if numeric:
            name = numeric.group(1)
            continue
        break
    return forms


def _secret_name_candidates(form: str) -> list[str]:
    """Names to test, including editor prefixes that hide a secret basename.

    Vim writes the swap for ``id_rsa`` as ``.id_rsa.swp`` and the swap for
    ``.env`` as ``..env.swp``. Emacs uses ``#id_rsa#`` and ``.#id_rsa``.
    Stripping those prefixes must still recognize the secret.
    """
    candidates: list[str] = []
    pending = [form]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if not current or current in seen:
            continue
        seen.add(current)
        candidates.append(current)
        if current.startswith(".") and len(current) > 1:
            pending.append(current[1:])
        if current.startswith("#") and current.endswith("#") and len(current) > 2:
            pending.append(current[1:-1])
        elif current.startswith("#") and len(current) > 1:
            pending.append(current[1:])
    return candidates


def _is_exact_live_config(filename: str) -> bool:
    """True only for the canonical config name, not a backup or aliased copy."""
    return filename.casefold().strip() in _LIVE_CONFIG_NAMES


def _candidate_is_secret(candidate: str) -> bool:
    """True when one normalized spelling is a secret, key, or database name."""
    if candidate in _SECRET_FILE_NAMES:
        return True
    if candidate == ".env" or candidate.startswith(".env."):
        return True
    if candidate == ".envrc" or candidate.startswith(".envrc."):
        return True
    if candidate.endswith(_SECRET_FILE_SUFFIXES):
        return True
    return _is_windows_short_secret(candidate)


def is_sensitive_filename(filename: str) -> bool:
    """True for secrets, databases, keys, and disguised copies of those files.

    Disguises include Windows 8.3 short names such as ``ENV~1``,
    ``ENVPRO~1.LOC`` for ``.env.production.local``, ``EN9DD6~1.LOC`` for
    ``.env.canary.local`` after short-name collisions, ``ENB38A~1.CAN`` for
    ``.env.canary``, and ``NOTIFI~1.JSO``.
    The canonical live config names stay readable through the JSON helpers;
    their short names do not.
    """
    for form in _filename_forms(filename):
        if any(_candidate_is_secret(candidate) for candidate in _secret_name_candidates(form)):
            return True
    return False


def _is_credential_file(path: Path, *, allow_live_config: bool = False) -> bool:
    """True when generic file helpers must not touch this path.

    JSON helpers may still read the live notification and API config files.
    A backup, trailing-dot, short-name, or alternate-data-stream alias of
    those files is refused, and CSV helpers refuse the live files too.
    """
    if allow_live_config and _is_exact_live_config(path.name):
        return False
    return is_sensitive_filename(path.name)


def resolve_project_path(path: Path | str, *, base: Path | None = None) -> Path:
    """Resolve a path and keep it inside the project root.

    Relative paths cannot escape the root. Absolute paths are accepted only
    when they already resolve inside the root. A symlinked final component is
    refused so a data file cannot be pointed at a credential file.
    """
    root = (base if base is not None else PROJECT_ROOT).resolve()
    raw = Path(path)
    if not raw.is_absolute():
        return confine_relative_path(raw, base=root)
    if raw.is_symlink():
        raise ValueError(f"Refusing to use a symlinked path: {raw}")
    resolved = raw.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path escapes the project root") from exc
    return resolved


def confine_relative_path(path: Path | str, *, base: Path | None = None) -> Path:
    """Resolve a relative path and keep it inside the project root.

    Absolute paths and a symlinked final component are rejected.
    """
    root = (base if base is not None else PROJECT_ROOT).resolve()
    raw = Path(path)
    if raw.is_absolute():
        raise ValueError("Absolute paths are not allowed")
    candidate = root / raw
    if candidate.is_symlink():
        raise ValueError("Refusing to use a symlinked path")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Path escapes the project root") from exc
    return resolved


def _nofollow_flags(flags: int) -> int:
    if hasattr(os, "O_NOFOLLOW"):
        return flags | os.O_NOFOLLOW
    return flags


def _raise_if_symlink_error(exc: OSError) -> None:
    if exc.errno == errno.ELOOP:
        raise ValueError("Refusing to follow a symlink") from exc


def open_unlinked_file(path: Path | str, flags: int, mode: int = 0o644) -> int:
    """Open a regular file that is neither a symlink nor a hard link.

    ``O_NOFOLLOW`` refuses a swapped-in symlink. A hard link is an ordinary
    directory entry for an inode that also has another name, so the same flag
    still opens it. ``O_TRUNC`` or ``O_APPEND`` would then change that other
    file, including a credential linked into the project. Truncation runs only
    after the opened inode has a single link.
    """
    file_path = Path(path)
    truncating = bool(flags & os.O_TRUNC)
    open_flags = _nofollow_flags(flags & ~os.O_TRUNC)
    try:
        fd = os.open(file_path, open_flags, mode)
    except OSError as exc:
        _raise_if_symlink_error(exc)
        raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Refusing to open a non-regular file: {file_path}")
        if info.st_nlink > 1:
            raise ValueError(f"Refusing to open a hard-linked file: {file_path}")
        if truncating:
            os.ftruncate(fd, 0)
    except Exception:
        os.close(fd)
        raise
    return fd


def read_nofollow_text(path: Path | str) -> str:
    """Read a text file without following a symlink or a hard link."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError(f"Refusing to read a symlinked file: {file_path}")
    fd = open_unlinked_file(file_path, os.O_RDONLY)
    try:
        handle = os.fdopen(fd, "r", encoding="utf-8")
        fd = -1
        with handle:
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def read_nofollow_bytes(path: Path | str) -> bytes:
    """Read a file without following a symlink or a hard link."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError(f"Refusing to read a symlinked file: {file_path}")
    fd = open_unlinked_file(file_path, os.O_RDONLY)
    try:
        handle = os.fdopen(fd, "rb")
        fd = -1
        with handle:
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def write_private_text(path: Path | str, content: str) -> Path:
    """Write text with mode 600 without following a symlink or a hard link."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError(f"Refusing to write through a symlink: {file_path}")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = open_unlinked_file(file_path, flags, 0o600)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1
        with handle:
            handle.write(content)
    finally:
        if fd >= 0:
            os.close(fd)
    return file_path


class JsonTokenCache:
    """OAuth token cache that will not follow a swapped-in symlink.

    Spotipy's file handler opens the path normally, so a ``.cache`` symlink
    can receive the refresh token or point the read at another secret.
    """

    def __init__(self, cache_path: Path | str) -> None:
        self.cache_path = Path(cache_path)

    def _cache_file(self) -> Path:
        path = resolve_project_path(self.cache_path)
        if path.name.casefold() != ".cache":
            raise ValueError("Token cache must be the .cache file")
        return path

    def get_cached_token(self) -> dict[str, Any] | None:
        """Return the cached token dictionary, or None when no cache exists."""
        try:
            raw = read_nofollow_text(self._cache_file())
        except FileNotFoundError:
            return None
        if not raw.strip():
            return None
        try:
            token = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(token, dict):
            return None
        return token

    def save_token_to_cache(self, token_info: dict[str, Any]) -> None:
        """Write a token dictionary with mode 600 without following a symlink."""
        write_private_text(self._cache_file(), json.dumps(token_info))


def ensure_private_file(path: Path | str) -> Path:
    """Create a secret file if needed and force mode 600 without following a symlink."""
    file_path = Path(path)
    if file_path.is_symlink():
        raise ValueError("Refusing to use a symlinked secret file")
    if not file_path.exists():
        return write_private_text(file_path, "")
    if os.name == "nt":
        return file_path
    fd = open_unlinked_file(file_path, os.O_RDONLY)
    try:
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    return file_path


def _csv_formula_probe(value: str) -> str:
    """Drop leading characters that spreadsheets ignore before a formula."""
    index = 0
    while index < len(value):
        category = unicodedata.category(value[index])
        if category[0] == "Z" or category in {"Cc", "Cf"}:
            index += 1
            continue
        break
    return value[index:]


def neutralize_csv_value(value: Any) -> Any:
    """Prefix spreadsheet formula and SYLK cells so exported CSV cannot execute them.

    Excel and LibreOffice skip leading spaces, tabs, newlines, nulls, and
    other invisible characters before deciding that a cell is a formula.
    A workbook whose first bytes are ``ID`` is opened as SYLK instead, and
    that parser can run commands, so the same prefix is quoted.
    """
    if not isinstance(value, str) or value == "":
        return value
    probed = _csv_formula_probe(value)
    if probed.startswith(_CSV_FORMULA_STARTS) or probed.startswith("ID"):
        return "'" + value
    return value


def neutralize_csv_frame(df: Any) -> Any:
    """Neutralize formula-looking cells and column headers in a DataFrame.

    ``DataFrame.to_csv`` writes column names into the header row. A header of
    ``=cmd`` is still a formula when every data cell has been prefixed.
    """
    neutralized = df.copy()
    renames: dict[str, str] = {}
    for column in neutralized.columns:
        if isinstance(column, str):
            safe_name = neutralize_csv_value(column)
            if isinstance(safe_name, str) and safe_name != column:
                renames[column] = safe_name
    if renames:
        neutralized = neutralized.rename(columns=renames)
    for column in neutralized.columns:
        neutralized[column] = neutralized[column].map(neutralize_csv_value)
    return neutralized


_SECRET_QUERY_RE = re.compile(
    r"(?i)\b(client_secret|secret_key|shared_secret|api_key|apikey|api_secret|"
    r"access_token|refresh_token|bot_token|token|password|passwd|secret|sig|signature|key)"
    r"=([^&\s\"']+)"
)
_SECRET_JSON_RE = re.compile(
    r"""(?i)(["'])(client_secret|secret_key|shared_secret|api_key|api_secret|"""
    r"""access_token|refresh_token|bot_token|password)\1\s*:\s*(["'])([^"']*)\3"""
)
_URL_USERINFO_RE = re.compile(r"(?i)(https?://)([^/\s:@]+):([^/\s@]+)@")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9\-._~+/]+=*")
_WEBHOOK_SECRET_RE = re.compile(
    r"(?i)https://(?:hooks\.slack\.com/services/\S+"
    r"|(?:[\w.-]+\.)?discord(?:app)?\.com/api/webhooks/\S+)"
)
_AUDIODB_KEY_RE = re.compile(r"(?i)(/api/v1/json/)([^/\s\"']+)")


def redact_secrets(value: Any) -> str:
    """Remove API keys, webhook URLs, and URL passwords from an error string."""
    text = str(value)
    text = _URL_USERINFO_RE.sub(r"\1REDACTED:REDACTED@", text)
    text = _SECRET_JSON_RE.sub(r"\1\2\1: \3REDACTED\3", text)
    text = _SECRET_QUERY_RE.sub(r"\1=REDACTED", text)
    text = _BEARER_RE.sub(r"\1REDACTED", text)
    text = _WEBHOOK_SECRET_RE.sub("https://webhook.invalid/REDACTED", text)
    text = _AUDIODB_KEY_RE.sub(r"\1REDACTED", text)
    return text


def is_loopback_http_host(host_header: str) -> bool:
    """True when a Host or Origin netloc is localhost or a loopback address."""
    if not isinstance(host_header, str):
        return False
    host = host_header.strip().lower()
    if (
        not host
        or any(ord(char) < 32 or ord(char) == 127 for char in host)
        or any(char in host for char in "\\@ ")
    ):
        return False
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            return False
        hostname = host[1:end]
        rest = host[end + 1 :]
        if rest and not re.fullmatch(r":[0-9]{1,5}", rest):
            return False
        if rest and not 0 < int(rest[1:]) <= 65535:
            return False
        return hostname == "::1"
    if host.count(":") > 1:
        return False
    hostname, separator, port = host.partition(":")
    if separator and (not port.isdigit() or not 0 < int(port) <= 65535):
        return False
    return hostname.rstrip(".") in {"localhost", "127.0.0.1"}


def _loopback_authority(host_header: str) -> tuple[str, int | None] | None:
    """Return a normalized loopback hostname and port, or None."""
    if not is_loopback_http_host(host_header):
        return None
    host = host_header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        hostname = host[1:end]
        rest = host[end + 1 :]
        port = int(rest[1:]) if rest else None
        return hostname, port
    hostname, separator, port_text = host.partition(":")
    port = int(port_text) if separator else None
    return hostname.rstrip("."), port


def dashboard_request_allowed(
    host: str,
    origin: str | None,
    sec_fetch_site: str | None,
    method: str = "GET",
) -> bool:
    """Allow the local dashboard and reject DNS rebinding and cross-site writes.

    A rebound name arrives with the attacker's Host header. A browser CSRF
    request to 127.0.0.1 arrives with the attacker's Origin. Another local
    port is a different origin even though ``Sec-Fetch-Site`` is ``same-site``,
    so unsafe methods must match this request's host and port exactly.
    """
    if not is_loopback_http_host(host):
        return False
    parsed = None
    if origin:
        parsed = urlparse(origin.strip())
        if parsed.scheme not in {"http", "https"} or not is_loopback_http_host(parsed.netloc):
            return False
    if method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return True
    if parsed is None:
        return False
    site = (sec_fetch_site or "").strip().lower()
    if site == "cross-site":
        return False
    return _loopback_authority(host) == _loopback_authority(parsed.netloc)


# JSON utilities
def read_json(path: Path | str, default: Any = None) -> Any:
    """
    Read JSON file safely.

    Args:
        path: Path to JSON file
        default: Value to return if file doesn't exist or is invalid

    Returns:
        Parsed JSON data or default value

    Raises:
        json.JSONDecodeError: If JSON is malformed and no default provided
    """
    path = resolve_project_path(path)
    if _is_credential_file(path, allow_live_config=True):
        raise ValueError(f"Refusing to read a credential file: {path.name}")
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symlinked JSON file: {path}")
    fd = -1
    try:
        fd = open_unlinked_file(path, os.O_RDONLY)
        handle = os.fdopen(fd, "r", encoding="utf-8")
        fd = -1
        with handle:
            return json.load(handle)
    except FileNotFoundError:
        if default is not None:
            logger.warning(f"JSON file not found: {path}, using default")
            return default
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {path}: {e}")
        if default is not None:
            return default
        raise
    except OSError as exc:
        _raise_if_symlink_error(exc)
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def write_json(
    path: Path | str,
    obj: Any,
    indent: int = 2,
    ensure_ascii: bool = False,
    create_dirs: bool = True,
    *,
    private: bool = False,
) -> Path:
    """
    Write JSON file safely.

    Args:
        path: Path to write JSON to
        obj: Object to serialize
        indent: JSON indentation level
        ensure_ascii: Whether to escape non-ASCII characters
        create_dirs: Whether to create parent directories

    Returns:
        Path object of the written file

    Raises:
        Exception: If writing fails
    """
    path = resolve_project_path(path)
    if _is_credential_file(path, allow_live_config=True):
        raise ValueError(f"Refusing to write a credential file: {path.name}")
    if path.is_symlink():
        raise ValueError(f"Refusing to write a symlinked JSON file: {path}")
    fd = -1
    try:
        if create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600 if private else 0o644
        fd = open_unlinked_file(path, flags, mode)
        if private and os.name != "nt":
            os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1
        with handle:
            json.dump(obj, handle, indent=indent, ensure_ascii=ensure_ascii, default=str)

        logger.debug(f"Wrote JSON to {path}")
        return path
    except OSError as exc:
        _raise_if_symlink_error(exc)
        logger.error(f"Failed to write JSON to {path}: {exc}")
        raise
    except Exception as e:
        logger.error(f"Failed to write JSON to {path}: {e}")
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def save_dataframe(df: Any, filepath: Path | str, create_dirs: bool = True) -> Path:  # pd.DataFrame
    """
    Save DataFrame to CSV with consistent settings.

    Args:
        df: DataFrame to save
        filepath: Path to save CSV to
        create_dirs: Whether to create parent directories

    Returns:
        Path object of the written file
    """
    filepath = resolve_project_path(filepath)
    if _is_credential_file(filepath):
        raise ValueError(f"Refusing to write a credential file: {filepath.name}")
    if filepath.is_symlink():
        raise ValueError(f"Refusing to write CSV through a symlink: {filepath}")

    if create_dirs:
        filepath.parent.mkdir(parents=True, exist_ok=True)

    frame = neutralize_csv_frame(df)
    fd = open_unlinked_file(filepath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        handle = os.fdopen(fd, "w", encoding="utf-8", newline="")
        fd = -1
        with handle:
            frame.to_csv(handle, index=False)
    finally:
        if fd >= 0:
            os.close(fd)
    logger.debug(f"Saved DataFrame to {filepath}")
    return filepath


@contextmanager
def open_project_writer(path: Path | str, *, binary: bool = False) -> Iterator[io.IOBase]:
    """Open a project file for overwrite without following a swapped-in symlink.

    Matplotlib and Plotly open the destination path themselves, so a chart
    name such as ``data/popularity_vs_rank.png`` can be replaced with a
    symlink or a hard link and the next save overwrites whatever that inode is.
    """
    file_path = resolve_project_path(path)
    if _is_credential_file(file_path):
        raise ValueError(f"Refusing to write a credential file: {file_path.name}")
    if file_path.is_symlink():
        raise ValueError(f"Refusing to write through a symlink: {file_path}")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = -1
    try:
        fd = open_unlinked_file(file_path, flags, 0o644)
        if os.name != "nt":
            os.fchmod(fd, 0o644)
        if binary:
            handle: io.IOBase = os.fdopen(fd, "wb")
        else:
            handle = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
        _raise_if_symlink_error(exc)
        raise
    try:
        yield handle
    finally:
        handle.close()


def save_matplotlib_figure(figure: Any, path: Path | str, **kwargs: Any) -> Path:
    """Save a matplotlib figure inside the project without following a symlink."""
    file_path = resolve_project_path(path)
    kwargs.setdefault("format", file_path.suffix.lstrip(".") or "png")
    with open_project_writer(file_path, binary=True) as handle:
        figure.savefig(handle, **kwargs)
    return file_path


def save_plotly_html(figure: Any, path: Path | str) -> Path:
    """Save a Plotly figure as HTML inside the project without following a symlink."""
    file_path = resolve_project_path(path)
    html = figure.to_html()
    if not isinstance(html, str):
        raise ValueError("Plotly HTML output must be text")
    with open_project_writer(file_path) as handle:
        handle.write(html)
    return file_path


def get_timestamp_filename(prefix: str = "", suffix: str = "") -> str:
    """
    Generate a filename with current timestamp.

    Args:
        prefix: String to prepend to timestamp
        suffix: String to append after timestamp

    Returns:
        Filename with format: {prefix}_{timestamp}_{suffix}

    Examples:
        >>> get_timestamp_filename("report", ".json")
        'report_20251010_143052.json'
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    parts = [p for p in [prefix, timestamp, suffix] if p]
    return "_".join(parts) if len(parts) > 1 else timestamp


# Data validation helpers
def validate_track_data(track: dict[str, Any], required_fields: list[str] | None = None) -> bool:
    """
    Validate track data structure.

    Args:
        track: Track dictionary to validate
        required_fields: List of required field names (default: id, name, artist)

    Returns:
        True if valid, False otherwise
    """
    if required_fields is None:
        required_fields = ["id", "name", "artist"]

    return all(field in track and track[field] for field in required_fields)


def safe_get_nested(data: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    """
    Safely get nested dictionary value.

    Args:
        data: Dictionary to traverse
        keys: List of keys to traverse in order
        default: Value to return if any key is missing

    Returns:
        Nested value or default

    Examples:
        >>> data = {"a": {"b": {"c": 42}}}
        >>> safe_get_nested(data, ["a", "b", "c"])
        42
        >>> safe_get_nested(data, ["a", "x", "y"], default=0)
        0
    """
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


# DataFrame utilities (requires pandas)
def load_dataframe(
    filepath: Path | str,
    required_columns: list[str] | None = None,
    default_empty: bool = True,
) -> Any:  # pd.DataFrame | None
    """
    Load DataFrame from CSV with error handling.

    Args:
        filepath: Path to CSV file
        required_columns: List of columns that must be present
        default_empty: Return empty DataFrame instead of None if file doesn't exist

    Returns:
        DataFrame or empty DataFrame (if default_empty=True) or None

    Examples:
        >>> df = load_dataframe("data/tracks.csv", required_columns=["id", "name"])
        >>> df = load_dataframe("missing.csv", default_empty=False)  # Returns None
    """
    if not HAS_PANDAS:
        raise ImportError("pandas is required for load_dataframe")

    filepath = resolve_project_path(filepath)
    if _is_credential_file(filepath):
        raise ValueError(f"Refusing to read a credential file: {filepath.name}")

    if not filepath.exists():
        logger.warning(f"CSV file not found: {filepath}")
        return pd.DataFrame() if default_empty else None

    try:
        df = pd.read_csv(io.StringIO(read_nofollow_text(filepath)))

        # Validate required columns
        if required_columns:
            missing = set(required_columns) - set(df.columns)
            if missing:
                logger.error(f"Missing required columns in {filepath}: {missing}")
                return pd.DataFrame() if default_empty else None

        logger.debug(f"Loaded DataFrame from {filepath} ({len(df)} rows)")
        return df

    except ValueError:
        # Symlink and hard-link refusals must surface. A missing or unreadable
        # CSV still falls through to the empty-frame path below.
        raise
    except Exception as e:
        logger.error(f"Failed to load CSV from {filepath}: {e}")
        return pd.DataFrame() if default_empty else None


def ensure_datetime_column(
    df: Any,  # pd.DataFrame
    column: str,
    date_formats: list[str] | None = None,
    errors: str = "coerce",
) -> Any:  # pd.DataFrame
    """
    Convert DataFrame column to datetime with fallback handling.

    Args:
        df: DataFrame to modify
        column: Column name to convert
        date_formats: List of date formats to try (None = auto-detect)
        errors: How to handle errors ('coerce', 'raise', 'ignore')

    Returns:
        DataFrame with converted column (modifies in place)

    Examples:
        >>> df = ensure_datetime_column(df, "played_at")
        >>> df = ensure_datetime_column(df, "timestamp", date_formats=["%Y-%m-%d"])
    """
    if not HAS_PANDAS:
        raise ImportError("pandas is required for ensure_datetime_column")

    if column not in df.columns:
        logger.warning(f"Column {column} not found in DataFrame")
        return df

    # Already datetime?
    if pd.api.types.is_datetime64_any_dtype(df[column]):
        return df

    # Try conversion
    try:
        if date_formats:
            # Try each format
            for fmt in date_formats:
                try:
                    df[column] = pd.to_datetime(df[column], format=fmt, errors=errors)
                    logger.debug(f"Converted {column} to datetime using format {fmt}")
                    return df
                except Exception:
                    continue
            # If all fail, use auto-detect
            df[column] = pd.to_datetime(df[column], errors=errors)
        else:
            # Auto-detect
            df[column] = pd.to_datetime(df[column], errors=errors)

        logger.debug(f"Converted {column} to datetime")
        return df

    except Exception as e:
        logger.error(f"Failed to convert {column} to datetime: {e}")
        return df


# Timestamp utilities
def get_iso_timestamp() -> str:
    """
    Get current timestamp in ISO 8601 format.

    Returns:
        ISO formatted timestamp string

    Examples:
        >>> ts = get_iso_timestamp()
        '2025-10-10T14:30:52.123456'
    """
    return datetime.now().isoformat()


def get_date_string(fmt: str = "%Y-%m-%d") -> str:
    """
    Get current date as formatted string.

    Args:
        fmt: strftime format string

    Returns:
        Formatted date string

    Examples:
        >>> get_date_string()
        '2025-10-10'
        >>> get_date_string("%Y%m%d")
        '20251010'
    """
    return datetime.now().strftime(fmt)


# Report generation helpers
def save_report(
    data: dict[str, Any],
    filename: str | None = None,
    prefix: str = "report",
    output_dir: str = "data/reports",
    add_timestamp: bool = True,
) -> Path:
    """
    Save a report/analysis to JSON with automatic timestamping and directory creation.

    Args:
        data: Dictionary data to save
        filename: Custom filename (if None, auto-generates with timestamp)
        prefix: Prefix for auto-generated filename
        output_dir: Directory to save report to
        add_timestamp: Whether to add timestamp to data (as 'timestamp' key)

    Returns:
        Path to saved report file

    Examples:
        >>> save_report({"analysis": "results"}, prefix="analytics")
        PosixPath('data/reports/analytics_20251010_143052.json')
        >>> save_report({"data": "test"}, filename="custom_report.json")
        PosixPath('data/reports/custom_report.json')
    """
    # Auto-generate filename if not provided
    if filename is None:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{timestamp_str}.json"

    safe_name = Path(filename).name
    if safe_name in {"", ".", ".."}:
        raise ValueError("Invalid report filename")
    filepath = confine_relative_path(Path(output_dir) / safe_name)
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Add timestamp to data if requested
    if add_timestamp and "timestamp" not in data:
        data = {**data, "timestamp": get_iso_timestamp()}

    # Save using write_json
    write_json(filepath, data)
    logger.info(f"Saved report to {filepath}")

    return filepath
