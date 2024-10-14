from kombu import uuid

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.models import AnalyzerReport, AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.yaraify import YARAify
from api_app.models import Job
from tests import CustomTestCase


class DataModelTestCase(CustomTestCase):

    def test_create_data_model(self):
        job = Job.objects.create(
            observable_name="test.com",
            observable_classification="domain",
            status=Job.Status.ANALYZERS_RUNNING.value,
        )
        config = AnalyzerConfig.objects.first()
        ar = AnalyzerReport.objects.create(
            report={"evaluation": "MALICIOUS"},
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        config: AnalyzerConfig
        config.mapping_data_model = {"evaluation": "evaluation"}
        config.save()
        job.analyzers_to_execute.set([config])
        obs = YARAify(config)
        obs.report = ar
        result = obs.create_data_model()
        self.assertIsNotNone(result)
        self.assertEqual(result.evaluation, "MALICIOUS")
