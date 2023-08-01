# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.core.exceptions import ValidationError

from api_app.validators import validate_runtime_configuration
from tests import CustomTestCase


class ValidateRuntimeConfigurationPlaybookTestCase(CustomTestCase):
    def test_validate_runtime_good(self):
        data = {
            "analyzers": {"analyzer": {"param": 123, "param2": "value"}},
            "connectors": {},
            "visualizers": {},
        }
        try:
            validate_runtime_configuration(data)
        except ValidationError as e:
            self.fail(e)

    def test_validate_runtime_wrong_additional_property(self):
        data = {
            "analyzers": {"analyzer": {"param": 123, "param2": "value"}},
            "connectors": {},
            "visualizers": {},
            "another_key": {},
        }
        with self.assertRaises(ValidationError):
            validate_runtime_configuration(data)

    def test_validate_runtime_wrong_missing_property(self):
        data = {"analyzers": {"analyzer": {"param": 123, "param2": "value"}}}
        with self.assertRaises(ValidationError):
            validate_runtime_configuration(data)

    def test_validate_runtime_wrong_typ(self):
        data = {
            "analyzers": [{"analyzer": {"param": 123, "param2": "value"}}],
            "connectors": {},
            "visualizers": {},
        }
        with self.assertRaises(ValidationError):
            validate_runtime_configuration(data)

        data = {
            "analyzers": {"analyzer": [{"param": 123, "param2": "value"}]},
            "connectors": {},
            "visualizers": {},
        }
        with self.assertRaises(ValidationError):
            validate_runtime_configuration(data)
