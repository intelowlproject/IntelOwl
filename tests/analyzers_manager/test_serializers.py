# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.test import TestCase

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer


class AnalyzerConfigTestCase(TestCase):
    def test_config_not_empty(self):
        config = AnalyzerConfigSerializer.read_and_verify_config()
        self.assertNotEqual(config, {})
