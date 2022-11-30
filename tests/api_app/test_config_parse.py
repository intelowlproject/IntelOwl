# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from unittest.mock import Mock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer

User = get_user_model()


class ConfigParseTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if User.objects.filter(username="test").exists():
            User.objects.get(username="test").delete()
        cls.superuser = User.objects.create_superuser(
            username="test", email="test@intelowl.com", password="test"
        )
        if not settings.STAGE_CI:
            call_command("migrate_secrets")

    @patch(
        "api_app.core.serializers.AbstractConfigSerializer._md5_config_file", new=Mock()
    )
    @patch("api_app.core.serializers.AbstractConfigSerializer._read_config")
    def test_extends(self, mock_read_config: Mock):
        sample_analyzer_config = {
            "Shodan_Honeyscore": {
                "type": "observable",
                "python_module": "shodan.Shodan",
                "description": "scan an IP against Shodan Honeyscore API",
                "disabled": False,
                "external_service": True,
                "leaks_info": False,
                "observable_supported": ["ip"],
                "config": {"soft_time_limit": 30, "queue": "default"},
                "secrets": {
                    "api_key_name": {
                        "env_var_key": "SHODAN_KEY",
                        "description": "",
                        "required": True,
                    }
                },
                "params": {
                    "shodan_analysis": {
                        "value": "honeyscore",
                        "type": "str",
                        "description": "",
                    }
                },
            },
            "Shodan_Search": {
                "extends": "Shodan_Honeyscore",
                "description": "scan an IP against Shodan Search API",
                "params": {
                    "shodan_analysis": {
                        "value": "search",
                        "type": "str",
                        "description": "",
                    }
                },
            },
        }

        pre_parsed_sample_config = {
            "Shodan_Honeyscore": {
                "type": "observable",
                "python_module": "shodan.Shodan",
                "description": "scan an IP against Shodan Honeyscore API",
                "disabled": False,
                "external_service": True,
                "leaks_info": False,
                "observable_supported": ["ip"],
                "config": {"soft_time_limit": 30, "queue": "default"},
                "secrets": {
                    "api_key_name": {
                        "env_var_key": "SHODAN_KEY",
                        "description": "",
                        "required": True,
                    }
                },
                "params": {
                    "shodan_analysis": {
                        "value": "honeyscore",
                        "type": "str",
                        "description": "",
                    }
                },
            },
            "Shodan_Search": {
                "type": "observable",
                "python_module": "shodan.Shodan",
                "disabled": False,
                "external_service": True,
                "leaks_info": False,
                "observable_supported": ["ip"],
                "config": {"soft_time_limit": 30, "queue": "default"},
                "secrets": {
                    "api_key_name": {
                        "env_var_key": "SHODAN_KEY",
                        "description": "",
                        "required": True,
                    }
                },
                "description": "scan an IP against Shodan Search API",
                "params": {
                    "shodan_analysis": {
                        "value": "search",
                        "type": "str",
                        "description": "",
                    }
                },
            },
        }

        mock_read_config.return_value = sample_analyzer_config
        # _refresh ensures that cache isn't used, if any
        parsed_config = AnalyzerConfigSerializer.read_and_verify_config(_refresh=True)

        mock_read_config.return_value = pre_parsed_sample_config
        expected_config = AnalyzerConfigSerializer.read_and_verify_config(_refresh=True)
        self.assertDictEqual(parsed_config, expected_config)
