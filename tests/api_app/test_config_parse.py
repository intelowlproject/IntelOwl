# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import random
from hashlib import md5

from django.test import TestCase

from api_app.core.serializers import AbstractConfigSerializer


class ModAbstractConfigSerializer(AbstractConfigSerializer):
    input_config = None

    @classmethod
    def _md5_config_file(cls) -> str:
        return md5(str(random.random()).encode("utf-8")).hexdigest()

    @classmethod
    def _read_config(cls):
        return cls.input_config


class ConfigParseTests(TestCase):
    def test_extends(self):
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

        ModAbstractConfigSerializer.input_config = sample_analyzer_config
        parsed_config = ModAbstractConfigSerializer.read_and_verify_config()

        ModAbstractConfigSerializer.input_config = pre_parsed_sample_config
        expected_config = ModAbstractConfigSerializer.read_and_verify_config()
        self.assertDictEqual(parsed_config, expected_config)
