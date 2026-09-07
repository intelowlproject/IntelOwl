from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification
from api_app.data_model_manager.models import IPDataModel
from api_app.models import Job
from tests import CustomTestCase


class CASDeduplicationTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        self.analyzable = Analyzable.objects.get_or_create(
            name="1.1.1.1", defaults={"classification": Classification.IP.value}
        )[0]
        self.job1 = Job.objects.create(
            analyzable=self.analyzable,
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
        )
        self.job2 = Job.objects.create(
            analyzable=self.analyzable,
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
        )
        self.config = AnalyzerConfig.objects.first()

    def test_smart_deduplication_via_fingerprint(self):
        report1 = AnalyzerReport.objects.create(
            job=self.job1,
            config=self.config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        report1._create_data_model_dictionary = lambda: {"isp": "Google", "asn": 15169}
        dm1 = report1.create_data_model()
        initial_count = IPDataModel.objects.count()

        report2 = AnalyzerReport.objects.create(
            job=self.job2,
            config=self.config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        report2._create_data_model_dictionary = lambda: {"isp": "Google", "asn": 15169}
        dm2 = report2.create_data_model()
        self.assertEqual(dm1.pk, dm2.pk)
        self.assertEqual(IPDataModel.objects.count(), initial_count)

    def test_normalization_stability(self):
        report1 = AnalyzerReport.objects.create(
            job=self.job1,
            config=self.config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        report1._create_data_model_dictionary = lambda: {"asn": 15169, "isp": "Google"}
        dm1 = report1.create_data_model()
        report2 = AnalyzerReport.objects.create(
            job=self.job2,
            config=self.config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        report2._create_data_model_dictionary = lambda: {"isp": "Google", "asn": 15169}
        dm2 = report2.create_data_model()
        self.assertEqual(dm1.fingerprint, dm2.fingerprint)
        self.assertEqual(dm1.pk, dm2.pk)
