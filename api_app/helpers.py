# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# general helper functions used by the Django API

import hashlib
import ipaddress
import logging
import random
import re

from django.utils import timezone
from magic import from_buffer as magic_from_buffer

from api_app.analyzers_manager.constants import ObservableTypes

logger = logging.getLogger(__name__)


def get_now_str():
    return str(timezone.now())


def get_now():
    return timezone.now()


def gen_random_colorhex() -> str:
    # flake8: noqa
    r = lambda: random.randint(0, 255)
    return "#%02X%02X%02X" % (r(), r(), r())


def calculate_mimetype(file_pointer, file_name) -> str:
    mimetype = None
    if file_name:
        if file_name.endswith(".js") or file_name.endswith(".jse"):
            mimetype = "application/javascript"
        elif file_name.endswith(".vbs") or file_name.endswith(".vbe"):
            mimetype = "application/x-vbscript"
        elif file_name.endswith(".iqy"):
            mimetype = "text/x-ms-iqy"
        elif file_name.endswith(".apk"):
            mimetype = "application/vnd.android.package-archive"
        elif file_name.endswith(".dex"):
            mimetype = "application/x-dex"
        elif file_name.endswith(".one"):
            mimetype = "application/onenote"

    if not mimetype:
        buffer = file_pointer.read()
        mimetype = magic_from_buffer(buffer, mime=True)

    return mimetype


def calculate_observable_classification(value: str) -> str:
    """Returns observable classification for the given value.\n
    Only following types are supported:
    ip, domain, url, hash (md5, sha1, sha256), generic (if no match)

    Args:
        value (str):
            observable value
    Returns:
        str: one of `ip`, `url`, `domain`, `hash` or 'generic'.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if re.match(
            r"^.+://[a-z\d-]{1,63}(?:\.[a-z\d-]{1,63})+"
            r"(?:/[a-zA-Z\d-]{1,63})*(?:\.\w+)?",
            value,
        ):
            classification = ObservableTypes.URL
        elif re.match(
            r"^([\[\\]?\.[\]\\]?)?[a-z\d-]{1,63}(([\[\\]?\.[\]\\]?)?[a-z\d-]{1,63})+$",
            value,
            re.IGNORECASE,
        ):
            classification = ObservableTypes.DOMAIN
        elif (
            re.match(r"^[a-f\d]{32}$", value, re.IGNORECASE)
            or re.match(r"^[a-f\d]{40}$", value, re.IGNORECASE)
            or re.match(r"^[a-f\d]{64}$", value, re.IGNORECASE)
        ):
            classification = ObservableTypes.HASH
        else:
            classification = ObservableTypes.GENERIC
            logger.info(
                f"Couldn't detect observable classification for {value}, setting as 'generic'..."
            )
    else:
        # it's a simple IP
        classification = ObservableTypes.IP

    return classification


def calculate_md5(value) -> str:
    return hashlib.md5(value).hexdigest()  # skipcq BAN-B324


def calculate_sha1(value) -> str:
    return hashlib.sha1(value).hexdigest()  # skipcq BAN-B324


def calculate_sha256(value) -> str:
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
