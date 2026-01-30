# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from django.core.exceptions import ValidationError
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification, PythonModuleBasePaths
from api_app.data_model_manager.models import DomainDataModel, IPDataModel
from api_app.models import Job, PythonModule
from tests import CustomTestCase


class AnalyzerReportTestCase(CustomTestCase):
    def test_clean(self):
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an1,
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
        )
        config = AnalyzerConfig.objects.first()
        ar: AnalyzerReport = AnalyzerReport.objects.create(
            report={
                "evaluation": "MALICIOUS",
                "urls": [{"url": "www.intelowl.com"}, {"url": "www.intelowl.com"}],
            },
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        ip_data_model = IPDataModel.objects.create()
        ar.data_model = ip_data_model
        with self.assertRaises(ValidationError):
            ar.full_clean()
        ip_data_model.delete()
        domain_data_model = DomainDataModel.objects.create()
        ar.data_model = domain_data_model
        ar.full_clean()
        ar.delete()
        job.delete()
        domain_data_model.delete()
        an1.delete()

    def test_create_data_model(self):
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an1,
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
        )
        config = AnalyzerConfig.objects.first()
        ar: AnalyzerReport = AnalyzerReport.objects.create(
            report={
                "evaluation": "MALICIOUS",
                "urls": [{"url": "www.intelowl.com"}, {"url": "www.intelowl.com"}],
            },
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        config: AnalyzerConfig
        config.mapping_data_model = {
            "evaluation": "evaluation",
            "urls.url": "external_references",
        }
        config.save()
        job.analyzers_to_execute.set([config])
        data_model = ar.create_data_model()
        data_model.refresh_from_db()
        self.assertIsNotNone(data_model)
        self.assertEqual(data_model.evaluation, "malicious")
        self.assertCountEqual(data_model.external_references, ["www.intelowl.com", "www.intelowl.com"])
        self.assertCountEqual([], ar.errors)
        data_model.delete()
        ar.delete()
        job.delete()
        an1.delete()

    def test_get_value(self):
        an1 = Analyzable.objects.create(
            name="test.com",
            classification=Classification.DOMAIN,
        )

        job = Job.objects.create(
            analyzable=an1,
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
        )
        config = AnalyzerConfig.objects.first()
        ar = AnalyzerReport.objects.create(
            report={
                "evaluation": "MALICIOUS",
                "urls": [{"url": "www.intelowl.com"}, {"url": "www.intelowl.com"}],
            },
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        self.assertEqual(ar.get_value(ar.report, ["evaluation"]), "MALICIOUS")
        self.assertEqual(ar.get_value(ar.report, "urls.0.url".split(".")), "www.intelowl.com")
        self.assertCountEqual(
            ar.get_value(ar.report, "urls.url".split(".")),
            ["www.intelowl.com", "www.intelowl.com"],
        )
        ar.delete()
        job.delete()
        an1.delete()


class AnalyzerConfigTestCase(CustomTestCase):
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
