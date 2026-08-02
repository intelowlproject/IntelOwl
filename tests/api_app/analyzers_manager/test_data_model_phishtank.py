# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from types import SimpleNamespace

from api_app.analyzers_manager.observable_analyzers.phishtank import Phishtank
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel
from tests import CustomTestCase


class PhishtankDataModelTestCase(CustomTestCase):
    @staticmethod
    def _phishtank(results):
        analyzer = Phishtank.__new__(Phishtank)
        analyzer.report = SimpleNamespace(
            report={"results": results},
            job=SimpleNamespace(analyzable=SimpleNamespace(classification=Classification.DOMAIN.value)),
        )
        analyzer._config = SimpleNamespace(mapping_data_model={})
        return analyzer

    def test_gate_requires_in_database(self):
        self.assertTrue(self._phishtank({"in_database": True})._do_create_data_model())
        self.assertFalse(self._phishtank({"in_database": False})._do_create_data_model())
        self.assertFalse(self._phishtank({})._do_create_data_model())

    def test_verified_hit_is_reliability_eight(self):
        dm = DomainDataModel()
        self._phishtank({"in_database": True, "verified": True})._update_data_model(dm)
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 8)

    def test_unverified_hit_is_reliability_five(self):
        dm = DomainDataModel()
        dm.reliability = 0  # sentinel: prove the code sets 5, not the field default (also 5)
        self._phishtank({"in_database": True, "verified": False})._update_data_model(dm)
        self.assertEqual(dm.evaluation, "malicious")
        self.assertEqual(dm.reliability, 5)
