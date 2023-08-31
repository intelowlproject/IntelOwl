import json

from django_celery_beat.models import CrontabSchedule, PeriodicTask

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import PythonModuleBasePaths
from api_app.models import PythonModule
from tests import CustomTestCase


class AnalyzerConfigSignalsTestCase(CustomTestCase):
    def test_pre_save_analyzer_config(self):
        crontab, created = CrontabSchedule.objects.get_or_create(minute=22)
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
            run_hash=False,
            update_schedule=crontab,
        )
        self.assertIsNotNone(ac.update_task)
        self.assertEqual(ac.update_task.name, "TestAnalyzer")
        self.assertEqual(ac.update_task.task, "intel_owl.tasks.update")
        # this is false because in the tests we have
        # REPO_DOWNLOADER_ENABLED set to False
        self.assertFalse(ac.update_task.enabled)
        self.assertEqual(ac.update_task.crontab, crontab)
        self.assertEqual(ac.update_task.queue, "default")
        self.assertEqual(json.loads(ac.update_task.kwargs)["config_pk"], ac.pk)
        ac.delete()
        if created:
            crontab.delete()

    def test_post_delete_analyzer_config(self):
        crontab, created = CrontabSchedule.objects.get_or_create(minute=22)
        ac = AnalyzerConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.FileAnalyzer.value,
                module="yara_scan.YaraScan",
            ),
            description="test",
            config={"soft_time_limit": 10, "queue": "default"},
            disabled=False,
            type="file",
            run_hash=False,
            update_schedule=crontab,
        )
        task = ac.update_task
        self.assertIsNotNone(task)
        task_pk = task.pk
        ac.delete()
        if created:
            crontab.delete()
        with self.assertRaises(PeriodicTask.DoesNotExist):
            PeriodicTask.objects.get(pk=task_pk)
