# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# general helper functions used by the Django API

import logging
import ipaddress
import re
from magic import from_buffer as magic_from_buffer

from django.utils import timezone

logger = logging.getLogger(__name__)


def get_now_str():
    return str(timezone.now())


def get_now():
    return timezone.now()


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

    if not mimetype:
        buffer = file_pointer.read()
        mimetype = magic_from_buffer(buffer, mime=True)

    return mimetype


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
