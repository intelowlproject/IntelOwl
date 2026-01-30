from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel
from api_app.data_model_manager.serializers import DomainDataModelSerializer
from api_app.models import Job
from tests import CustomTestCase


class TestDomainDataModelSerializer(CustomTestCase):
    def test_to_representation(self):
        analyzable = Analyzable.objects.create(name="test.com", classification=Classification.DOMAIN)
        job = Job.objects.create(
            status=Job.STATUSES.ANALYZERS_RUNNING.value,
            analyzable=analyzable,
        )
        config = AnalyzerConfig.objects.first()
        dm = DomainDataModel.objects.create(evaluation="malicious")
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

        ar.data_model = dm
        ar.save()
        dm.refresh_from_db()

        ser = DomainDataModelSerializer(dm)
        result = ser.data
        self.assertEqual(result["evaluation"], "malicious")

        dm.delete()
        ar.delete()
        job.delete()
        analyzable.delete()
