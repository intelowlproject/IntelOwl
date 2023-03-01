from django.core.exceptions import ValidationError

from api_app.validators import (
    validate_config,
    validate_params,
    validate_runtime_configuration_playbook,
    validate_secrets,
)
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
                "env_var_key": "KEY",
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
                "env_var_key": "KEY",
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
                "env_var_key": "KEY",
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
                "env_var_key": "KEY",
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
                "env_var_key": "KEY",
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
                "env_var_key": 123,
                "description": "description",
                "required": True,
                "type": "str",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

        data = {
            "key": {
                "env_var_key": "KEY",
                "description": 123,
                "required": True,
                "type": "str",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

        data = {
            "key": {
                "env_var_key": "KEY",
                "description": "description",
                "required": 123,
                "type": "str",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)

        data = {
            "key": {
                "env_var_key": "KEY",
                "description": "description",
                "required": True,
                "type": "string",
            }
        }
        with self.assertRaises(ValidationError):
            validate_secrets(data)


class ValidateParamsTestCase(CustomTestCase):
    def test_validate_params_good(self):
        data = {"param": {"type": "str", "description": "description"}}
        try:
            validate_params(data)
        except ValidationError as e:
            self.fail(e)

    def test_validate_params_missing_property(self):
        data = {"param": {"description": "description"}}
        with self.assertRaises(ValidationError):
            validate_params(data)

    def test_validate_params_additional_property(self):
        data = {"param": {"type": "str", "description": "description", "value": 123}}
        with self.assertRaises(ValidationError):
            validate_params(data)

    def test_validate_params_wrong_pattern(self):
        data = {
            "123param": {
                "type": "str",
                "description": "description",
            }
        }
        with self.assertRaises(ValidationError):
            validate_params(data)

    def test_validate_params_wrong_type(self):
        data = {
            "param": {
                "type": "string",
                "description": "description",
            }
        }
        with self.assertRaises(ValidationError):
            validate_params(data)

        data = {
            "param": {
                "type": "str",
                "description": 123,
            }
        }
        with self.assertRaises(ValidationError):
            validate_params(data)


class ValidateRuntimeConfigurationPlaybookTestCase(CustomTestCase):
    def test_validate_runtime_good(self):
        data = {
            "analyzers": {"analyzer": {"param": 123, "param2": "value"}},
            "connectors": {},
        }
        try:
            validate_runtime_configuration_playbook(data)
        except ValidationError as e:
            self.fail(e)

    def test_validate_runtime_wrong_additional_property(self):
        data = {
            "analyzers": {"analyzer": {"param": 123, "param2": "value"}},
            "connectors": {},
            "another_key": {},
        }
        with self.assertRaises(ValidationError):
            validate_runtime_configuration_playbook(data)

    def test_validate_runtime_wrong_missing_property(self):
        data = {"analyzers": {"analyzer": {"param": 123, "param2": "value"}}}
        with self.assertRaises(ValidationError):
            validate_runtime_configuration_playbook(data)

    def test_validate_runtime_wrong_typ(self):
        data = {
            "analyzers": [{"analyzer": {"param": 123, "param2": "value"}}],
            "connectors": {},
        }
        with self.assertRaises(ValidationError):
            validate_runtime_configuration_playbook(data)

        data = {
            "analyzers": {"analyzer": [{"param": 123, "param2": "value"}]},
            "connectors": {},
        }
        with self.assertRaises(ValidationError):
            validate_runtime_configuration_playbook(data)
