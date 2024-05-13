import json

from django_celery_beat.models import CrontabSchedule, PeriodicTask

from api_app.choices import PythonModuleBasePaths
from api_app.ingestors_manager.models import IngestorConfig
from api_app.models import PythonModule
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.user.models import User
from tests import CustomTestCase


class IngestorConfigSignalsTestCase(CustomTestCase):
    def test_pre_save_ingestor_config(self):
        crontab, created = CrontabSchedule.objects.get_or_create(minute=22)
        ic = IngestorConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Ingestor.value,
                module="threatfox.ThreatFox",
            ),
            description="test",
            disabled=True,
            schedule=crontab,
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        self.assertIsNotNone(ic.periodic_task)
        self.assertEqual(ic.periodic_task.name, "TestIngestor")
        self.assertEqual(ic.periodic_task.task, "intel_owl.tasks.execute_ingestor")
        self.assertFalse(ic.periodic_task.enabled)
        self.assertEqual(ic.periodic_task.crontab, crontab)
        self.assertEqual(ic.periodic_task.queue, "default")
        self.assertEqual(json.loads(ic.periodic_task.kwargs)["config_name"], ic.name)
        self.assertIsNotNone(ic.user)
        self.assertEqual(ic.user.username, "TestIngestor")
        ic.delete()
        if created:
            crontab.delete()

    def test_post_delete_ingestor_config(self):
        crontab, created = CrontabSchedule.objects.get_or_create(minute=22)
        ic = IngestorConfig.objects.create(
            name="test",
            python_module=PythonModule.objects.get(
                base_path=PythonModuleBasePaths.Ingestor.value,
                module="threatfox.ThreatFox",
            ),
            description="test",
            disabled=True,
            schedule=crontab,
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        user = ic.user
        task = ic.periodic_task
        self.assertIsNotNone(task)
        self.assertIsNotNone(user)
        task_pk = task.pk
        user_pk = user.pk
        ic.delete()
        with self.assertRaises(PeriodicTask.DoesNotExist):
            PeriodicTask.objects.get(pk=task_pk)
        with self.assertRaises(User.DoesNotExist):
            User.objects.get(pk=user_pk)
        if created:
            crontab.delete()
