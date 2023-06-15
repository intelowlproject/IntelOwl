from django.core.exceptions import ValidationError

from api_app.pivots_manager.validators import pivot_regex_validator
from tests import CustomTestCase


class PivotRegexValidatorTestCase(CustomTestCase):
    def test_valid(self):
        pivot_regex_validator("test")
        pivot_regex_validator("test.t")
        pivot_regex_validator("test.test")
        pivot_regex_validator("test.test.0")
        pivot_regex_validator("test.test.0.te_st")

    def test_invalid(self):
        with self.assertRaises(ValidationError):
            pivot_regex_validator(".test")
        with self.assertRaises(ValidationError):
            pivot_regex_validator("test.")
        with self.assertRaises(ValidationError):
            pivot_regex_validator("test.test.")
        with self.assertRaises(ValidationError):
            pivot_regex_validator("test.test!")
        with self.assertRaises(ValidationError):
            pivot_regex_validator("test.test,")
        with self.assertRaises(ValidationError):
            pivot_regex_validator("test.test?")
        with self.assertRaises(ValidationError):
            pivot_regex_validator("test.test?")
