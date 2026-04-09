# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib.auth.password_validation import validate_password as django_validate_password
from django.core.exceptions import ValidationError

REGEX_EMAIL = r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$"
REGEX_CVE = r"CVE-\d{4}-\d{4,7}"


def validate_password_strength(password: str, user=None) -> None:
    """Validate password using Django's built-in validators.

    Uses AUTH_PASSWORD_VALIDATORS from settings which includes:
    - UserAttributeSimilarityValidator (requires user context)
    - MinimumLengthValidator (12 characters)
    - CommonPasswordValidator
    - NumericPasswordValidator

    Raises ValidationError if password is invalid.
    """
    try:
        django_validate_password(password, user=user)
    except ValidationError as e:
        # Re-raise with combined error messages
        raise ValidationError("; ".join(e.messages))


DEFAULT_SOFT_TIME_LIMIT = 300
