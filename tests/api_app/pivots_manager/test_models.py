from django.core.exceptions import ValidationError
from django.db import transaction

from api_app.analyzers_manager.constants import AllTypes
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job, PythonModule
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.user.models import User
from tests import CustomTestCase


class PivotConfigTestCase(CustomTestCase):
    def test_clean_multiple_config(self):
        pc = PivotConfig.objects.create(
            name="test",
            description="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        ac = AnalyzerConfig.objects.first()
        pc.related_analyzer_configs.set([ac])
        self.assertIn(ac.name, pc.description)
        with transaction.atomic(), self.assertRaises(ValidationError):
            pc.related_connector_configs.set([ConnectorConfig.objects.first()])
        self.assertFalse(pc.related_connector_configs.exists())
        pc.delete()

    def test_clean_valid(self):
        pc = PivotConfig(
            name="test",
            description="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        try:
            pc.full_clean()
        except ValidationError as e:
            self.fail(e)

    def test_field_validation_valid(self):
        pc = PivotConfig(
            name="test",
            description="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        try:
            pc.full_clean()
        except ValidationError as e:
            self.fail(e)

    def test_create_job_multiple_generic(self):
        playbook = PlaybookConfig.objects.create(
            type=["generic"],
            name="test123",
            description="test123",
        )
        ac2 = AnalyzerConfig.objects.filter(
            observable_supported__contains=["generic"],
            python_module__parameters__isnull=True,
        ).first()
        playbook.analyzers.set([ac2])
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=playbook,
        )

        jobs = list(
            pc.create_jobs(
                ["something", "something2"], job.tlp, job.user, send_task=False
            )
        )
        self.assertEqual(2, len(jobs))
        self.assertEqual("something", jobs[0].observable_name)
        self.assertEqual("generic", jobs[0].observable_classification)

        self.assertEqual("something2", jobs[1].observable_name)
        self.assertEqual("generic", jobs[1].observable_classification)
        playbook.delete()

    def test_create_job_multiple_file(self):
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            name="PivotOnTest",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.filter(
                disabled=False, type__icontains=AllTypes.FILE.value
            ).first(),
        )
        with open("test_files/file.exe", "rb") as f:
            content = f.read()
        jobs = list(pc.create_jobs(content, job.tlp, job.user, send_task=False))
        self.assertEqual(1, len(jobs))
        self.assertEqual("PivotOnTest.0", jobs[0].file_name)
        self.assertEqual(
            "application/vnd.microsoft.portable-executable", jobs[0].file_mimetype
        )

    def test_create_job(self):
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.filter(type=["domain"]).first(),
        )
        jobs = list(pc.create_jobs("google.com", job.tlp, job.user, send_task=False))
        self.assertEqual(1, len(jobs))
        self.assertEqual("google.com", jobs[0].observable_name)
        self.assertEqual("domain", jobs[0].observable_classification)
