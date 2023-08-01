# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.core.exceptions import ValidationError

from api_app.validators import validate_config, validate_params, validate_secrets
from tests import CustomTestCase


class ValidateConfigTestCase(CustomTestCase):
    def validate_config_good(self):
        data = {"soft_time_limit": 123, "queue": "default"}
        try:
            validate_config(data)
        except ValidationError as e:
            self.fail(e)

    def validate_config_wrong_type(self):
        data = {"soft_time_limit": "123", "queue": "default"}
        with self.assertRaises(ValidationError):
            validate_config(data)

        data = {"soft_time_limit": "default", "queue": 123}
        with self.assertRaises(ValidationError):
            validate_config(data)

    def validate_config_missing_key(self):
        data = {
            "soft_time_limit": 123,
        }
        with self.assertRaises(ValidationError):
            validate_config(data)

        data = {
            "queue": "default",
        }
        with self.assertRaises(ValidationError):
            validate_config(data)

    def validate_config_additional_key(self):
        data = {"soft_time_limit": 123, "queue": "default", "another_key": "key"}
        with self.assertRaises(ValidationError):
            validate_config(data)


class ValidateSecretsTestCase(CustomTestCase):
    def validate_secrets_good(self):
        data = {
            "key": {
                "description": "description",
                "required": True,
                "type": "str",
                "default": "default_value",
            }
        }
        try:
            validate_secrets(data)
        except ValidationError as e:
            self.fail(e)

    def validate_secrets_bad_pattern(self):
        data = {
            "123key": {
                "description": "description",
                "required": True,
                "type": "str",
                "default": "default_value",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

    def validate_secrets_additional_properties(self):
        data = {
            "key": {
                "description": "description",
                "required": True,
                "type": "str",
                "default": "default_value",
                "another_one": "error",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

    def validate_secrets_missing_properties(self):
        data = {
            "key": {
                "description": "description",
                "required": True,
                "default": "default_value",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

    def validate_secrets_default_optional(self):
        data = {
            "key": {
                "description": "description",
                "required": True,
                "type": "str",
            }
        }
        try:
            validate_secrets(data)
        except ValidationError as e:
            self.fail(e)

    def validate_secrets_wrong_type(self):
        data = {
            "key": {
                "description": 123,
                "required": True,
                "type": "str",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

        data = {
            "key": {
                "description": "description",
                "required": 123,
                "type": "str",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

        data = {
            "key": {
                "description": "description",
                "required": True,
                "type": "string",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)


class ValidateParamsTestCase(CustomTestCase):
    def test_validate_params_good(self):
        data = {
            "param": {"type": "str", "description": "description", "default": "value"}
        }
        try:
            validate_params(data)
        except ValidationError as e:
            self.fail(e)

    def test_validate_params_missing_property(self):
        data = {"param": {"description": "description"}}
        with self.assertRaises(ValidationError):
            validate_params(data)

    def test_validate_params_additional_property(self):
        data = {
            "param": {
                "type": "str",
                "description": "description",
                "default": "value",
                "error": 123,
            }
        }
        with self.assertRaises(ValidationError):
            validate_params(data)

    def test_validate_params_wrong_pattern(self):
        data = {
            "123param": {
                "type": "str",
                "description": "description",
                "default": "value",
            }
        }
        with self.assertRaises(ValidationError):
            validate_params(data)

    def test_validate_params_wrong_type(self):
        data = {
            "param": {
                "type": "string",
                "description": "description",
                "default": "value",
            }
        }
        with self.assertRaises(ValidationError):
            validate_params(data)

        data = {"param": {"type": "str", "description": 123, "default": "value"}}
        with self.assertRaises(ValidationError):
            validate_params(data)
