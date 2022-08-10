# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from unittest.mock import Mock, patch

from django.test import TestCase

from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer


class ConfigParseTests(TestCase):
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
