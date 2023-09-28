from django.core.exceptions import ValidationError
from django.db import IntegrityError

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job, PythonModule
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from certego_saas.apps.user.models import User
from tests import CustomTestCase


class PivotConfigTestCase(CustomTestCase):
    def test_clean_multiple_config(self):
        pc = PivotConfig(
            name="test",
            description="test",
            related_analyzer_config=AnalyzerConfig.objects.first(),
            related_connector_config=ConnectorConfig.objects.first(),
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_constraint_no_config(self):
        pc = PivotConfig(
            name="test",
            description="test",
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(IntegrityError):
            pc.save()

    def test_clean_valid(self):
        pc = PivotConfig(
            name="test",
            description="test",
            related_analyzer_config=AnalyzerConfig.objects.first(),
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
            related_analyzer_config=AnalyzerConfig.objects.first(),
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        try:
            pc.full_clean()
        except ValidationError as e:
            self.fail(e)

    def test_field_validation_start_dotted(self):
        pc = PivotConfig(
            name="test",
            description="test",
            related_analyzer_config=AnalyzerConfig.objects.first(),
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_field_validation_end_dotted(self):
        pc = PivotConfig(
            name="test",
            description="test",
            related_analyzer_config=AnalyzerConfig.objects.first(),
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_field_validation_invalid_char(self):
        pc = PivotConfig(
            name="test",
            description="test",
            related_analyzer_config=AnalyzerConfig.objects.first(),
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

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
        ac = AnalyzerConfig.objects.filter().first()
        playbook.analyzers.set([ac2])
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            related_analyzer_config=ac,
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=playbook,
        )

        jobs = list(
            pc._create_jobs(
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
        ac = AnalyzerConfig.objects.first()
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            name="PivotOnTest",
            related_analyzer_config=ac,
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.filter(type=["file"]).first(),
        )
        with open("test_files/file.exe", "rb") as f:
            content = f.read()
        jobs = list(pc._create_jobs(content, job.tlp, job.user, send_task=False))
        self.assertEqual(1, len(jobs))
        self.assertEqual("PivotOnTest.0", jobs[0].file_name)
        self.assertEqual("application/x-dosexec", jobs[0].file_mimetype)

    def test_create_job(self):
        ac = AnalyzerConfig.objects.first()
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            related_analyzer_config=ac,
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            playbook_to_execute=PlaybookConfig.objects.filter(type=["domain"]).first(),
        )
        jobs = list(pc._create_jobs("google.com", job.tlp, job.user, send_task=False))
        self.assertEqual(1, len(jobs))
        self.assertEqual("google.com", jobs[0].observable_name)
        self.assertEqual("domain", jobs[0].observable_classification)
