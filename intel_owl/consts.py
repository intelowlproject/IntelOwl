# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re

from django.core.exceptions import ValidationError

REGEX_EMAIL = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
REGEX_CVE = r"CVE-\d{4}-\d{4,7}"
REGEX_PASSWORD = r"^[a-zA-Z0-9]{12,}$"


def validate_password_strength(password: str) -> None:
    """Validate password against REGEX_PASSWORD. Raises ValidationError if invalid."""
    if not re.match(REGEX_PASSWORD, password):
        raise ValidationError("Invalid password")


DEFAULT_SOFT_TIME_LIMIT = 300
