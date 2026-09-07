# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class CharacterDiversityValidator:
    """
    Validate that the password contains characters from at least 3 of
    the following 4 categories: uppercase letters, lowercase letters,
    digits, and special characters.
    """

    def validate(self, password, user=None):  # skipcq: PYL-R0201
        """
        Validate that the password contains characters from at least 3 categories.

        Args:
            password (str): The password to validate.
            user (User, optional): The user object to validate against (unused).

        Raises:
            ValidationError: If the password contains characters from fewer than 3 categories.
        """
        categories = 0
        if re.search(r"[A-Z]", password):
            categories += 1
        if re.search(r"[a-z]", password):
            categories += 1
        if re.search(r"[0-9]", password):
            categories += 1
        if re.search(r"[^A-Za-z0-9]", password):
            categories += 1

        if categories < 3:
            raise ValidationError(
                _(
                    "The password must contain characters from at least 3 of "
                    "the following: uppercase letters, lowercase letters, "
                    "digits, and special characters."
                ),
                code="insufficient_character_diversity",
            )

    def get_help_text(self):  # skipcq: PYL-R0201
        """
        Return the help text for the character diversity validator.

        Returns:
            str: Help text explaining the password diversity requirements.
        """
        return _(
            "Your password must contain characters from at least 3 of "
            "the following: uppercase letters, lowercase letters, "
            "digits, and special characters."
        )
