# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# general helper functions used by the Django API

import hashlib
import ipaddress
import logging
import random
import re
import typing
import warnings

from django.utils import timezone

SENSITIVE_KEYS = {
    "password",
    "token",
    "auth",
    "secret",
    "key",
    "credential",
    "signature",
}


def mask_sensitive_data(value: typing.Any, is_secret: bool = True) -> typing.Any:
    """
    Returns "<redacted>" if is_secret is True, otherwise returns the value.
    """
    if is_secret:
        return "<redacted>"
    return value


def mask_recursive(data: typing.Any) -> typing.Any:
    """
    Recursively masks sensitive keys in dictionaries and lists.
    Uses word-boundary/camelCase aware matching to avoid false positives.
    """
    if isinstance(data, dict):
        masked_dict = {}
        for k, v in data.items():
            if isinstance(k, str):
                # Tokenize key to handle camelCase, snake_case, and kebab-case
                # Split on camelCase boundaries and non-alphanumeric delimiters
                tokens = re.sub("([a-z0-9])([A-Z])", r"\1 \2", k).lower()
                tokens = re.split(r"[^a-z0-9]", tokens)

                if any(tk in SENSITIVE_KEYS for tk in tokens):
                    masked_dict[k] = "<redacted>"
                else:
                    masked_dict[k] = mask_recursive(v)
            else:
                masked_dict[k] = mask_recursive(v)
        return masked_dict
    elif isinstance(data, list):
        return [mask_recursive(item) for item in data]
    return data


logger = logging.getLogger(__name__)


def get_now_str():
    return str(timezone.now())


def get_now():
    return timezone.now()


def gen_random_colorhex() -> str:
    # flake8: noqa
    r = lambda: random.randint(0, 255)
    return "#%02X%02X%02X" % (r(), r(), r())


def calculate_md5(value: bytes) -> str:
    return hashlib.md5(value).hexdigest()  # skipcq BAN-B324


def calculate_sha1(value: bytes) -> str:
    return hashlib.sha1(value).hexdigest()  # skipcq BAN-B324


def calculate_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()  # skipcq BAN-B324


def get_ip_version(ip_value):
    """
    Returns ip version
    Supports IPv4 and IPv6
    """
    ip_type = None
    try:
        ip = ipaddress.ip_address(ip_value)
        ip_type = ip.version
    except ValueError as e:
        logger.error(e)
    return ip_type


def get_hash_type(hash_value):
    """
    Returns hash type
    Supports md5, sha1, sha256 and sha512
    """
    RE_HASH_MAP = {
        "md5": re.compile(r"^[a-f\d]{32}$", re.IGNORECASE | re.ASCII),
        "sha-1": re.compile(r"^[a-f\d]{40}$", re.IGNORECASE | re.ASCII),
        "sha-256": re.compile(r"^[a-f\d]{64}$", re.IGNORECASE | re.ASCII),
        "sha-512": re.compile(r"^[a-f\d]{128}$", re.IGNORECASE | re.ASCII),
    }

    detected_hash_type = None
    for hash_type, re_hash in RE_HASH_MAP.items():
        if re.match(re_hash, hash_value):
            detected_hash_type = hash_type
            break
    return detected_hash_type  # stays None if no matches


def deprecated(message: str):
    def decorator(func):
        def wrapper(*args, **kwargs):
            warnings.warn(message, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)

        return wrapper

    return decorator
