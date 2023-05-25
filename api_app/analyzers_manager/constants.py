# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import ipaddress
import re
from logging import getLogger

from django.db import models

logger = getLogger(__name__)


class TypeChoices(models.TextChoices):
    FILE = "file"
    OBSERVABLE = "observable"


class HashChoices(models.TextChoices):
    MD5 = "md5"
    SHA256 = "sha256"


class ObservableTypes(models.TextChoices):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"

    @classmethod
    def calculate(cls, value: str) -> str:
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
                r"^.+://[a-z\d-]{1,200}"
                r"(?:\.[a-zA-Z\d\u2044\u2215!#$&(-;=?-\[\]_~]{1,200})+"
                r"(?::\d{2,6})?"
                r"(?:/[a-zA-Z\d\u2044\u2215!#$&(-;=?-\[\]_~]{1,200})*"
                r"(?:\.\w+)?",
                value,
            ):
                classification = cls.URL
            elif re.match(
                r"^([\[\\]?\.[\]\\]?)?[a-z\d-]{1,63}"
                r"(([\[\\]?\.[\]\\]?)[a-z\d-]{1,63})+$",
                value,
                re.IGNORECASE,
            ):
                classification = cls.DOMAIN
            elif (
                re.match(r"^[a-f\d]{32}$", value, re.IGNORECASE)
                or re.match(r"^[a-f\d]{40}$", value, re.IGNORECASE)
                or re.match(r"^[a-f\d]{64}$", value, re.IGNORECASE)
            ):
                classification = cls.HASH
            else:
                classification = cls.GENERIC
                logger.info(
                    "Couldn't detect observable classification"
                    f" for {value}, setting as 'generic'"
                )
        else:
            # it's a simple IP
            classification = cls.IP

        return classification


class AllTypes(models.TextChoices):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"
    FILE = "file"
