from django.utils.timezone import now
from kombu import uuid

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.data_model_manager.models import IPDataModel
from api_app.engines_manager.engines.evaluation import EvaluationEngineModule
from api_app.models import Job
from tests import CustomTestCase


class EvaluationEngineModuleTestCase(CustomTestCase):

    def test_run(self):
        job = Job.objects.create(
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            observable_name="8.8.8.8",
            observable_classification=ObservableTypes.IP,
            received_request_time=now(),
        )
        config = EvaluationEngineModule(job)
        ar2 = AnalyzerReport.objects.create(
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
            job=job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="VirusTotal_v3_Get_Observable"),
        )

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
            job=job,
            task_id=uuid(),
            config=AnalyzerConfig.objects.get(name="OTXQuery"),
        )

        ip1 = IPDataModel.objects.create(
            evaluation=IPDataModel.EVALUATIONS.MALICIOUS.value,
            resolutions=["1.2.3.4"],
        )
        ip2 = IPDataModel.objects.create(
            resolutions=["1.2.3.5"],
            evaluation=IPDataModel.EVALUATIONS.SUSPICIOUS.value,
        )
        ar.data_model = ip1
        ar.save()
        ar2.data_model = ip2
        ar2.save()

        job.refresh_from_db()
        self.assertEqual(2, job.get_analyzers_data_models().count())
        result = config.run()
        self.assertEqual(result["evaluation"], IPDataModel.EVALUATIONS.MALICIOUS.value)
        ar.delete()
        ar2.delete()
        job.delete()
        ip1.delete()
        ip2.delete()
