# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import random
from hashlib import md5
from unittest.mock import Mock, patch

from django.test import TestCase

from api_app.core.serializers import AbstractConfigSerializer


class ConfigParseTests(TestCase):
    @patch("api_app.core.serializers.AbstractConfigSerializer._md5_config_file")
    @patch("api_app.core.serializers.AbstractConfigSerializer._read_config")
    def test_extends(self, mock_read_config: Mock, mock_md5_config_file: Mock):
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
            "Shodan_Honeyscore": sample_analyzer_config["Shodan_Honeyscore"],
            "Shodan_Search": {
                **sample_analyzer_config["Shodan_Honeyscore"],
                **sample_analyzer_config["Shodan_Search"],
            },
        }
        pre_parsed_sample_config["Shodan_Search"].pop("extends")

        mock_read_config.return_value = sample_analyzer_config
        mock_md5_config_file.return_value = md5(
            str(random.random()).encode("utf-8")
        ).hexdigest()
        parsed_config = AbstractConfigSerializer.read_and_verify_config()

        mock_read_config.return_value = pre_parsed_sample_config
        mock_md5_config_file.return_value = md5(
            str(random.random()).encode("utf-8")
        ).hexdigest()
        expected_config = AbstractConfigSerializer.read_and_verify_config()
        self.assertDictEqual(parsed_config, expected_config)
