# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from types import SimpleNamespace

from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.analyzers_manager.observable_analyzers.phishing_army import PhishingArmy
from api_app.analyzers_manager.observable_analyzers.phishstats import PhishStats
from api_app.choices import Classification
from api_app.models import Job
from tests import CustomTestCase


class PhishingListsGateTestCase(CustomTestCase):
    @staticmethod
    def _stub(analyzer_cls, report_dict):
        analyzer = analyzer_cls.__new__(analyzer_cls)
        analyzer.report = SimpleNamespace(
            report=report_dict,
            job=SimpleNamespace(analyzable=SimpleNamespace(classification=Classification.DOMAIN.value)),
        )
        analyzer._config = SimpleNamespace(mapping_data_model={"$malicious": "evaluation"})
        return analyzer

    def test_phishing_army_gate(self):
        self.assertTrue(self._stub(PhishingArmy, {"found": True})._do_create_data_model())
        self.assertFalse(self._stub(PhishingArmy, {"found": False})._do_create_data_model())

    def test_phishstats_gate(self):
        self.assertTrue(self._stub(PhishStats, {"results": [{"id": 1}]})._do_create_data_model())
        self.assertFalse(self._stub(PhishStats, {"results": []})._do_create_data_model())

    def test_phishing_army_mapping_reliability_six(self):
        an = Analyzable.objects.create(name="bad.com", classification=Classification.DOMAIN)
        job = Job.objects.create(analyzable=an, status=Job.STATUSES.ANALYZERS_RUNNING.value)
        config = AnalyzerConfig.objects.get(name="PhishingArmy")
        ar = AnalyzerReport.objects.create(
            report={"found": True, "link": "x"},
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        job.analyzers_to_execute.set([config])
        dm = ar.create_data_model()
        dm.refresh_from_db()
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 6)
