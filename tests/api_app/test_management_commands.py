# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, tag

from api_app.models import PluginCredential


@tag("x")
class ConfigParseTests(TestCase):
    def test_extends(self):
        def _patched_get_env_var(name):
            if name == "SHODAN_KEY":
                return "12345"
            else:
                return None

        with patch(
            "api_app.management.commands.migrate_secrets.Command._get_env_var",
            _patched_get_env_var,
        ):
            call_command("migrate_secrets")
        self.assertTrue(
            PluginCredential.objects.filter(
                attribute="api_key_name",
                value="12345",
                plugin_name="Shodan_Honeyscore",
                type=PluginCredential.PluginType.ANALYZER,
            ).exists()
        )
