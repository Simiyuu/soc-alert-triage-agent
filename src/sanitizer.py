import re
import unicodedata
from typing import Any, Dict
from src.models import UnifiedAuthRecord

ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def sanitize_string(value: str, max_length: int = 256) -> str:
    """Cleans a string by stripping ANSI sequences, control characters, null bytes,

    and applying Unicode NFKC normalization and length clamping.
    """
    if not value:
        return ""

    # 1. Strip ANSI escape codes
    text = ANSI_ESCAPE_PATTERN.sub("", value)

    # 2. Replace carriage returns and newlines with spaces to prevent CWE-117 log forging
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")

    # 3. Strip null bytes and non-printable control characters
    cleaned_chars = []
    for char in text:
        if char == "\t" or (unicodedata.category(char) != "Cc" and ord(char) >= 32):
            cleaned_chars.append(char)

    text = "".join(cleaned_chars)

    # 4. Canonical Unicode Normalization (NFKC)
    text = unicodedata.normalize("NFKC", text).strip()

    # 5. Length bounding
    if len(text) > max_length:
        text = text[:max_length]

    return text


def sanitize_auth_record(record: UnifiedAuthRecord) -> UnifiedAuthRecord:
    """Sanitizes username, hostname, service, and string metadata fields within a UnifiedAuthRecord."""
    record.username = sanitize_string(record.username, max_length=128)
    record.hostname = sanitize_string(record.hostname, max_length=128)
    record.service = sanitize_string(record.service, max_length=64)

    if record.metadata:
        sanitized_meta: Dict[str, Any] = {}
        for k, v in record.metadata.items():
            clean_k = sanitize_string(str(k), max_length=64)
            if isinstance(v, str):
                sanitized_meta[clean_k] = sanitize_string(v, max_length=256)
            else:
                sanitized_meta[clean_k] = v
        record.metadata = sanitized_meta

    return record