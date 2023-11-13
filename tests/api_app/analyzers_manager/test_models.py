# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.exceptions import ValidationError
from django_celery_beat.models import CrontabSchedule

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import PythonModuleBasePaths
from api_app.models import PythonModule
from tests import CustomTestCase


class AnalyzerConfigTestCase(CustomTestCase):
    def test_clean_update_schedule(self):
        crontab, created = CrontabSchedule.objects.get_or_create(minute=19)
        ac = AnalyzerConfig(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
                module="tranco.Tranco",
            ),
            description="test",
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
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            disabled=False,
            type="file",
            run_hash=False,
            update_schedule=crontab,
        )
        ac.clean_update_schedule()
        if created:
            crontab.delete()

    def test_clean_run_hash_type(self):
        ac = AnalyzerConfig(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
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
