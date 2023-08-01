# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig
from tests import CustomTestCase


class AnalyzerConfigTestCase(CustomTestCase):
    def test_clean_python_module_hash(self):
        ac = AnalyzerConfig(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
            run_hash=True,
        )
        with self.assertRaises(ValidationError) as e:
            ac.clean_python_module()
        self.assertEqual(1, len(e.exception.messages))
        self.assertEqual(
            "`python_module` incorrect, "
            "api_app.analyzers_manager.observable_analyzers.yara_scan.YaraScan"
            " couldn't be imported",
            e.exception.messages[0],
        )

    def test_clean_run_hash_type(self):
        ac = AnalyzerConfig(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
            run_hash=True,
        )
        with self.assertRaises(ValidationError) as e:
            ac.clean_run_hash_type()
        self.assertEqual(1, len(e.exception.messages))
        self.assertEqual(
            "run_hash_type must be populated if run_hash is True",
            e.exception.messages[0],
        )
        ac.delete()

    def test_update(self):
        from intel_owl import tasks

        result = tasks.update("yara_scan.YaraScan2")
        self.assertFalse(result)

        ac = AnalyzerConfig(
            name="test",
            python_module="xlm_macro_deobfuscator.XlmMacroDeobfuscator",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
        )
        result = tasks.update("xlm_macro_deobfuscator.XlmMacroDeobfuscator")
        self.assertFalse(result)
        ac.delete()

        ac = AnalyzerConfig(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
        )
        with patch("intel_owl.celery.broadcast"):
            result = tasks.update("yara_scan.YaraScan")
        self.assertTrue(result)
        ac.delete()
