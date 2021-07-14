# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from enum import Enum
import typing


class AnalyzerConfigEnum(Enum):
    @classmethod
    def aslist(cls) -> list:
        return [c.value for c in cls]

    @classmethod
    def as_type(cls) -> typing.Literal:
        return typing.Literal[cls.aslist()]


class TypeChoices(AnalyzerConfigEnum):
    FILE = "file"
    OBSERVABLE = "observable"


class HashChoices(AnalyzerConfigEnum):
    MD5 = "md5"
    SHA256 = "sha256"


class ObservableTypes(AnalyzerConfigEnum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"
