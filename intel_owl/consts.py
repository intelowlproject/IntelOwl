# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from enum import Enum

REGEX_EMAIL = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
REGEX_CVE = r"CVE-\d{4}-\d{4,7}"

DEFAULT_QUEUE = "default"
DEFAULT_SOFT_TIME_LIMIT = 300
PARAM_DATATYPE_CHOICES = ["int", "float", "str", "bool", "list", "dict"]


class ObservableClassification(Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    HASH = "hash"
    GENERIC = "generic"

    @staticmethod
    def all():
        return [c for c in ObservableClassification]
