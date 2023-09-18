import uuid

from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job, PythonModule
from api_app.pivots_manager.models import PivotConfig
from api_app.playbooks_manager.models import PlaybookConfig
from api_app.visualizers_manager.models import VisualizerConfig
from certego_saas.apps.user.models import User
from tests import CustomTestCase


class PivotConfigTestCase(CustomTestCase):
    def test_clean_multiple_config(self):
        pc = PivotConfig(
            name="test",
            description="test",
            analyzer_config=AnalyzerConfig.objects.first(),
            connector_config=ConnectorConfig.objects.first(),
            visualizer_config=VisualizerConfig.objects.first(),
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_clean_no_config(self):
        pc = PivotConfig(
            name="test",
            description="test",
            field_to_compare="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_clean_valid(self):
        pc = PivotConfig(
            name="test",
            description="test",
            analyzer_config=AnalyzerConfig.objects.first(),
            field_to_compare="test",
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
            field_to_compare="test",
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
            field_to_compare=".test",
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
            field_to_compare="test.",
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
            field_to_compare="test!",
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
        ac = AnalyzerConfig.objects.first()
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            related_analyzer_config=ac,
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            field_to_compare="test",
            playbook_to_execute=playbook,
        )

        report = AnalyzerReport(
            report={"test": ["something", "something2"]}, config=ac, job=job
        )
        jobs = list(
            pc._create_jobs(report, report.job.tlp, report.job.user, send_task=False)
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
            field_to_compare="test",
            playbook_to_execute=PlaybookConfig.objects.filter(type=["file"]).first(),
        )
        with open("test_files/file.exe", "rb") as f:
            content = f.read()
        report = AnalyzerReport(report={"test": [content]}, config=ac, job=job)
        jobs = list(
            pc._create_jobs(report, report.job.tlp, report.job.user, send_task=False)
        )
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
            field_to_compare="test",
            playbook_to_execute=PlaybookConfig.objects.filter(type=["domain"]).first(),
        )
        report = AnalyzerReport(report={"test": "google.com"}, config=ac, job=job)
        jobs = list(
            pc._create_jobs(report, report.job.tlp, report.job.user, send_task=False)
        )
        self.assertEqual(1, len(jobs))
        self.assertEqual("google.com", jobs[0].observable_name)
        self.assertEqual("domain", jobs[0].observable_classification)

    def test_pivot_job_invalid_report(self):
        ac = AnalyzerConfig.objects.first()
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            related_analyzer_config=ac,
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            field_to_compare="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        self.assertCountEqual([], pc.pivot_job(job))

    def test_pivot_job_invalid_value(self):
        ac = AnalyzerConfig.objects.first()
        job = Job.objects.create(
            observable_name="test.com",
            tlp="AMBER",
            user=User.objects.first(),
        )
        pc = PivotConfig(
            related_analyzer_config=ac,
            python_module=PythonModule.objects.filter(
                base_path="api_app.pivots_manager.pivots"
            ).first(),
            field_to_compare="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        report = AnalyzerReport.objects.create(
            report={"test": 123}, config=ac, job=job, task_id=uuid.uuid4()
        )
        self.assertCountEqual([], pc.pivot_job(job))
        report.delete()
        job.delete()
