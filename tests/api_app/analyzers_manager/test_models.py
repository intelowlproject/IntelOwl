# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from django.core.exceptions import ValidationError
from django_celery_beat.models import CrontabSchedule

from api_app.analyzers_manager.models import AnalyzerConfig
from tests import CustomTestCase


class AnalyzerConfigTestCase(CustomTestCase):
    def test_clean_update_schedule(self):
        crontab, created = CrontabSchedule.objects.get_or_create(minute=19)
        ac = AnalyzerConfig(
            name="test",
            python_module="tranco.Tranco",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="observable",
            run_hash=False,
            update_schedule=crontab,
        )
        with self.assertRaises(ValidationError) as e:
            ac.clean_update_schedule()
        self.assertEqual(1, len(e.exception.messages))
        self.assertEqual(
            "You can't configure an update schedule if"
            " the python class does not support that.",
            e.exception.messages[0],
        )
        ac = AnalyzerConfig(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
            run_hash=False,
            update_schedule=crontab,
        )
        ac.clean_update_schedule()
        if created:
            crontab.delete()

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

        with self.assertRaises(AnalyzerConfig.DoesNotExist):
            tasks.update("yara_scan.YaraScan2")

        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module="xlm_macro_deobfuscator.XlmMacroDeobfuscator",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
        )
        result = tasks.update("test")
        self.assertFalse(result)
        ac.delete()

        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module="yara_scan.YaraScan",
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
        )
        with patch("intel_owl.celery.broadcast"):
            result = tasks.update("test")
        self.assertTrue(result)
        ac.delete()
