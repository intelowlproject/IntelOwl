from django.utils.timezone import now
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification
from api_app.data_model_manager.models import IPDataModel
from api_app.engines_manager.engines.evaluation import EvaluationEngineModule
from api_app.engines_manager.engines.malware_family import MalwareFamilyEngineModule
from api_app.models import Job
from tests import CustomTestCase


class EngineModuleTestCase(CustomTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.an = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )
        self.job = Job.objects.create(
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            received_request_time=now(),
            analyzable=self.an,
        )
        self.ars = []

    def execute(self, module, *data_models):
        for i, dm in enumerate(data_models):
            ar = AnalyzerReport.objects.create(
                parameters={},
                report={
                    "passive_dns": [
                        {
                            "address": "195.22.26.248",
                            "first": "2022-03-19T17:14:00",
                            "last": "2022-03-19T17:16:33",
                            "hostname": "4ed8a7c6.ard.rr.zealbino.com",
                            "record_type": "A",
                            "indicator_link": "/indicator/hostname/4ed8a7c6.ard.rr.zealbino.com",  # noqa: E501
                            "flag_url": "assets/images/flags/pt.png",
                            "flag_title": "Portugal",
                            "asset_type": "hostname",
                            "asn": "AS8426 claranet ltd",
                            "suspicious": True,
                            "whitelisted_message": [],
                            "whitelisted": False,
                        },
                    ],
                },
                job=self.job,
                task_id=uuid(),
                config=AnalyzerConfig.objects.filter(
                    observable_supported__contains=[Classification.IP.value]
                )[i],
            )
            ar.data_model = dm
            ar.save()
            self.ars.append(ar)
        self.job.refresh_from_db()
        return module.run()

    def tearDown(self) -> None:
        self.job.delete()
        self.an.delete()
        for ar in self.ars:
            ar.delete()

    def test_malware_family(self):
        config = MalwareFamilyEngineModule(self.job)

        ip1 = IPDataModel.objects.create(
            evaluation=IPDataModel.EVALUATIONS.MALICIOUS.value,
            reliability=8,
            resolutions=["1.2.3.4"],
            malware_family="test2",
        )
        ip3 = IPDataModel.objects.create(
            resolutions=["1.2.3.5"],
            evaluation=IPDataModel.EVALUATIONS.TRUSTED.value,
            reliability=2,
            malware_family="test2",
        )

        result = self.execute(config, ip1, ip3)
        self.assertEqual(result["evaluation"], IPDataModel.EVALUATIONS.MALICIOUS.value)
        self.assertEqual(result["malware_family"], "test2")

        ip1.delete()
        ip3.delete()

    def test_evaluation(self):
        config = EvaluationEngineModule(self.job)

        ip1 = IPDataModel.objects.create(
            evaluation=IPDataModel.EVALUATIONS.MALICIOUS.value,
            resolutions=["1.2.3.4"],
            reliability=8,
        )
        ip2 = IPDataModel.objects.create(
            resolutions=["1.2.3.5"],
            evaluation=IPDataModel.EVALUATIONS.TRUSTED.value,
            reliability=2,
        )

        result = self.execute(config, ip1, ip2)
        self.assertEqual(result["evaluation"], IPDataModel.EVALUATIONS.MALICIOUS.value)

        ip1.delete()
        ip2.delete()
