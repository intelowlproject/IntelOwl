# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

REGEX_EMAIL = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
REGEX_CVE = r"CVE-\d{4}-\d{4,7}"


def validate_password_strength(password: str, user=None) -> None:
    """Validate password using Django's AUTH_PASSWORD_VALIDATORS.

    Raises ValidationError if invalid. Optionally accepts a user object
    to enable UserAttributeSimilarityValidator checks.
    """
    try:
        validate_password(password, user=user)
    except ValidationError as e:
        raise ValidationError(e.messages)


DEFAULT_SOFT_TIME_LIMIT = 300
