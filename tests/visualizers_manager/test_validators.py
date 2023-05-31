# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.core.exceptions import ValidationError

from api_app.visualizers_manager.validators import validate_report
from tests import CustomTestCase


class ValidateReportTestCase(CustomTestCase):
    def test_validate_report_good(self):
        data = {"attribute": {"value": "myvalue", "priority": 1, "position": "left"}}
        try:
            validate_report(data)
        except ValidationError as e:
            self.fail(e)

    def test_validate_report_wrong_priority(self):
        data = {"attribute": {"value": "myvalue", "priority": 0, "position": "left"}}
        with self.assertRaises(ValidationError):
            validate_report(data)

    def test_validate_report_wrong_position(self):
        data = {"attribute": {"value": "myvalue", "priority": 1, "position": "what"}}
        with self.assertRaises(ValidationError):
            validate_report(data)
