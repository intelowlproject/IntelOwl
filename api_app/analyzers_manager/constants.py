# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from enum import Enum


class TypeChoices(Enum):
    FILE = "file"
    OBSERVABLE = "observable"

    @classmethod
    def aslist(cls) -> list:
        return [c.value for c in cls]


class HashChoices(Enum):
    MD5 = "md5"
    SHA256 = "sha256"

    @classmethod
    def aslist(cls) -> list:
        return [c.value for c in cls]


class ObservableTypes(Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"

    @classmethod
    def aslist(cls) -> list:
        return [c.value for c in cls]
