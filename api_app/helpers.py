# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# general helper functions used by the Django API

import hashlib
import ipaddress
import logging
import random
import re
import warnings

from django.utils import timezone

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
