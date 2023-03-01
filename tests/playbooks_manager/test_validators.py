from django.core.exceptions import ValidationError

from api_app.playbooks_manager.validators import validate_runtime_configuration_playbook
from tests import CustomTestCase


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
