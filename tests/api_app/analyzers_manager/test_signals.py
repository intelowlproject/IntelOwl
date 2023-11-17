import json

from django_celery_beat.models import CrontabSchedule

from api_app.choices import PythonModuleBasePaths
from api_app.models import PythonModule
from tests import CustomTestCase


class AnalyzerConfigSignalsTestCase(CustomTestCase):
    def test_pre_save_analyzer_config(self):
        pm = PythonModule.objects.get(
            base_path=PythonModuleBasePaths.ObservableAnalyzer.value,
            module="cyberchef.CyberChef",
        )
        self.assertIsNone(pm.update_task)

        pm: PythonModule

        pm.update_schedule = CrontabSchedule.objects.create(hour=2, minute=2)
        pm.save()
        self.assertIsNotNone(pm.update_task)
        self.assertEqual(pm.update_task.name, pm.python_complete_path + "Update")
        self.assertEqual(pm.update_task.task, "intel_owl.tasks.update")
        # this is false because in the tests we have
        # REPO_DOWNLOADER_ENABLED set to False
        self.assertFalse(pm.update_task.enabled)
        self.assertEqual(pm.update_task.queue, pm.configs.first().queue)
        self.assertEqual(json.loads(pm.update_task.kwargs)["python_module_pk"], pm.pk)
