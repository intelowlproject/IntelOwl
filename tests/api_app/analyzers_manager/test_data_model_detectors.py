# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from types import SimpleNamespace

from kombu import uuid

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.adguard import (
    AdGuard,
)
from api_app.choices import Classification
from api_app.models import Job
from tests import CustomTestCase


def _gate_stub(analyzer_cls, report_dict, mapping=None):
    """Build a minimally-initialised analyzer to exercise _do_create_data_model
    without a full plugin construction (mirrors how the base gate reads state)."""
    analyzer = analyzer_cls.__new__(analyzer_cls)
    analyzer.report = SimpleNamespace(
        report=report_dict,
        job=SimpleNamespace(analyzable=SimpleNamespace(classification=Classification.DOMAIN.value)),
    )
    analyzer._config = SimpleNamespace(mapping_data_model=mapping or {"$malicious": "evaluation"})
    return analyzer


class MaliciousDetectorGateTestCase(CustomTestCase):
    def test_gate_emits_only_on_real_hit(self):
        self.assertTrue(_gate_stub(AdGuard, {"malicious": True})._do_create_data_model())

    def test_gate_suppresses_clean_lookup(self):
        # F1: the $malicious constant would stamp MALICIOUS on every clean lookup;
        # the gate must return False so NO data model is created.
        self.assertFalse(_gate_stub(AdGuard, {"malicious": False})._do_create_data_model())

    def test_gate_suppresses_timeout_and_note(self):
        self.assertFalse(_gate_stub(AdGuard, {"malicious": False, "timeout": True})._do_create_data_model())
        self.assertFalse(
            _gate_stub(
                AdGuard, {"malicious": False, "note": "No response from AdGuard DNS API"}
            )._do_create_data_model()
        )


class MaliciousDetectorMappingTestCase(CustomTestCase):
    def _run_mapping(self, config_name, report_dict):
        an = Analyzable.objects.create(name="test.com", classification=Classification.DOMAIN)
        job = Job.objects.create(analyzable=an, status=Job.STATUSES.ANALYZERS_RUNNING.value)
        config = AnalyzerConfig.objects.get(name=config_name)
        ar = AnalyzerReport.objects.create(
            report=report_dict,
            job=job,
            config=config,
            status=AnalyzerReport.STATUSES.SUCCESS.value,
            task_id=str(uuid()),
            parameters={},
        )
        job.analyzers_to_execute.set([config])
        data_model = ar.create_data_model()  # report-level: applies mapping only
        if data_model is not None:
            data_model.refresh_from_db()
        return data_model

    def test_adguard_mapping_sets_malicious_reliability_six(self):
        dm = self._run_mapping("AdGuard", {"observable": "test.com", "malicious": True})
        self.assertIsNotNone(dm)
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 6)

    def test_googlewebrisk_mapping_sets_reliability_eight(self):
        dm = self._run_mapping("GoogleWebRisk", {"observable": "test.com", "malicious": True})
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 8)

    def test_spamhaus_mapping_sets_reliability_seven(self):
        dm = self._run_mapping("Spamhaus_WQS", {"observable": "test.com", "malicious": True})
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 7)
