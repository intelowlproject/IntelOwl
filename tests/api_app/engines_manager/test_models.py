from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.timezone import now
from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification
from api_app.data_model_manager.models import IPDataModel
from api_app.engines_manager.models import EngineConfig
from api_app.models import Job
from tests import CustomTestCase


class EngineConfigTestCase(CustomTestCase):
    def test_create_multiple_config(self):
        with self.assertRaises(Exception), transaction.atomic():
            EngineConfig.objects.create()
        self.assertEqual(EngineConfig.objects.count(), 1)

    def test_clean(self):
        config = EngineConfig.objects.first()
        config.modules.append("test.Test")
        with self.assertRaises(ValidationError):
            config.full_clean()
        config.delete()

    def test_run_empty(self):
        an1 = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )

        config = EngineConfig.objects.first()
        job = Job.objects.create(
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            analyzable=an1,
            received_request_time=now(),
        )
        config.run(job)
        job.refresh_from_db()
        self.assertIsNotNone(job.data_model)
        self.assertIsNone(
            job.data_model.evaluation,
        )
        job.delete()
        config.delete()
        an1.delete()

    def test_run_value(self):
        an1 = Analyzable.objects.create(
            name="8.8.8.8",
            classification=Classification.IP,
        )

        config = EngineConfig.objects.first()
        job = Job.objects.create(
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            analyzable=an1,
            received_request_time=now(),
        )
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
        ip2 = IPDataModel.objects.create(resolutions=["1.2.3.5"])
        ar.data_model = ip1
        ar.save()
        ar2.data_model = ip2
        ar2.save()

        job.refresh_from_db()
        self.assertEqual(2, job.get_analyzers_data_models().count())
        config.run(job)
        self.assertEqual(job.data_model.evaluation, job.data_model.EVALUATIONS.MALICIOUS.value)
        self.assertCountEqual(job.data_model.resolutions, ip1.resolutions + ip2.resolutions)
        ar.delete()
        ar2.delete()
        job.delete()
        ip1.delete()
        ip2.delete()
        config.delete()
        job.delete()
        an1.delete()

    def test_run_generic(self):
        an1 = Analyzable.objects.create(
            name="test@intelowl.com",
            classification=Classification.GENERIC,
        )

        config = EngineConfig.objects.first()
        job = Job.objects.create(
            user=self.user,
            status=Job.STATUSES.REPORTED_WITHOUT_FAILS.value,
            analyzable=an1,
            received_request_time=now(),
        )
        config.run(job)
        job.refresh_from_db()
        self.assertIsNone(job.data_model)
        job.delete()
        config.delete()
        an1.delete()
