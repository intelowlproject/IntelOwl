import uuid

from django.core.exceptions import ValidationError

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.connectors_manager.models import ConnectorConfig
from api_app.models import Job
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
            analyzer=AnalyzerConfig.objects.first(),
            connector=ConnectorConfig.objects.first(),
            visualizer=VisualizerConfig.objects.first(),
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_clean_no_config(self):
        pc = PivotConfig(
            name="test",
            description="test",
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_clean_valid(self):
        pc = PivotConfig(
            name="test",
            description="test",
            analyzer=AnalyzerConfig.objects.first(),
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        pc.full_clean()

    def test_field_validation_valid(self):
        pc = PivotConfig(
            name="test",
            description="test",
            analyzer=AnalyzerConfig.objects.first(),
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        pc.full_clean()

    def test_field_validation_start_dotted(self):
        pc = PivotConfig(
            name="test",
            description="test",
            analyzer=AnalyzerConfig.objects.first(),
            field=".test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_field_validation_end_dotted(self):
        pc = PivotConfig(
            name="test",
            description="test",
            analyzer=AnalyzerConfig.objects.first(),
            field="test.",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_field_validation_invalid_char(self):
        pc = PivotConfig(
            name="test",
            description="test",
            analyzer=AnalyzerConfig.objects.first(),
            field="test!",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        with self.assertRaises(ValidationError):
            pc.full_clean()

    def test_config(self):
        pc = PivotConfig(
            analyzer=AnalyzerConfig.objects.first(),
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        self.assertIsInstance(pc.config, AnalyzerConfig)

    def test_get_value_str(self):
        ac = AnalyzerConfig.objects.first()
        pc = PivotConfig(
            analyzer=ac,
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        report = AnalyzerReport(report={"test": "abc"}, config=ac)

        self.assertEqual("abc", next(pc.get_value(report)))

    def test_get_value_list(self):
        ac = AnalyzerConfig.objects.first()
        pc = PivotConfig(
            analyzer=ac,
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        report = AnalyzerReport(report={"test": ["abc", "edf"]}, config=ac)
        self.assertCountEqual(["abc", "edf"], list(pc.get_value(report)))
        pc.field = "test.0"
        self.assertEqual("abc", next(pc.get_value(report)))

    def test_get_value_dict(self):
        ac = AnalyzerConfig.objects.first()
        pc = PivotConfig(
            analyzer=ac,
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        report = AnalyzerReport(report={"test": {"test2": "abc"}}, config=ac)

        with self.assertRaises(ValueError):
            next(pc.get_value(report))
        pc.field = "test.test2"
        self.assertEqual("abc", next(pc.get_value(report)))

    def test_get_value_bytes(self):
        ac = AnalyzerConfig.objects.first()
        pc = PivotConfig(
            analyzer=ac,
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        report = AnalyzerReport(report={"test": b"abc"}, config=ac)

        with self.assertRaises(ValueError):
            next(pc.get_value(report))

    def test_create_job_multiple_generic(self):

        ac = AnalyzerConfig.objects.first()
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            analyzer=ac,
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )

        report = AnalyzerReport(
            report={"test": ["something", "something2"]}, config=ac, job=job
        )
        jobs = list(pc._create_jobs(report, send_task=False))
        self.assertEqual(2, len(jobs))
        self.assertEqual("something", jobs[0].observable_name)
        self.assertEqual("generic", jobs[0].observable_classification)

        self.assertEqual("something2", jobs[1].observable_name)
        self.assertEqual("generic", jobs[1].observable_classification)

    def test_create_job(self):
        ac = AnalyzerConfig.objects.first()
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            analyzer=ac,
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        report = AnalyzerReport(report={"test": "google.com"}, config=ac, job=job)
        jobs = list(pc._create_jobs(report, send_task=False))
        self.assertEqual(1, len(jobs))
        self.assertEqual("google.com", jobs[0].observable_name)
        self.assertEqual("domain", jobs[0].observable_classification)

    def test_pivot_job_invalid_report(self):
        ac = AnalyzerConfig.objects.first()
        job = Job(observable_name="test.com", tlp="AMBER", user=User.objects.first())
        pc = PivotConfig(
            analyzer=ac,
            field="test",
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
            analyzer=ac,
            field="test",
            playbook_to_execute=PlaybookConfig.objects.first(),
        )
        report = AnalyzerReport.objects.create(
            report={"test": 123}, config=ac, job=job, task_id=uuid.uuid4()
        )
        self.assertCountEqual([], pc.pivot_job(job))
        report.delete()
        job.delete()
