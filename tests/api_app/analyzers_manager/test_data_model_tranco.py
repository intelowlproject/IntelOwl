# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from types import SimpleNamespace

from api_app.analyzers_manager.observable_analyzers.tranco import Tranco
from api_app.choices import Classification
from api_app.data_model_manager.models import DomainDataModel
from tests import CustomTestCase


class TrancoDataModelTestCase(CustomTestCase):
    @staticmethod
    def _tranco(report_dict):
        analyzer = Tranco.__new__(Tranco)
        analyzer.report = SimpleNamespace(
            report=report_dict,
            job=SimpleNamespace(analyzable=SimpleNamespace(classification=Classification.DOMAIN.value)),
        )
        analyzer._config = SimpleNamespace(mapping_data_model={})
        return analyzer

    def test_gate_requires_positive_rank(self):
        self.assertTrue(self._tranco({"rank": 5000})._do_create_data_model())
        self.assertFalse(self._tranco({"rank": None})._do_create_data_model())
        self.assertFalse(self._tranco({})._do_create_data_model())

    def test_rank_bands(self):
        # The top-1000 band is the only one that reaches the "trusted" bucket (floor 8); every
        # boundary is pinned on both sides so a band edit cannot silently widen or shrink it.
        for rank, expected in [
            (1, 9),
            (1000, 9),
            (1001, 4),
            (10000, 4),
            (10001, 3),
            (100000, 3),
            (100001, 2),
        ]:
            dm = DomainDataModel()
            self._tranco({"rank": rank})._update_data_model(dm)
            self.assertEqual(dm.evaluation, "trusted")
            self.assertEqual(dm.reliability, expected, f"rank={rank}")

    def test_malformed_report_never_raises(self):
        # a blocklist miss must never yield trusted; malformed input must not crash
        self.assertFalse(self._tranco({"unexpected": "shape"})._do_create_data_model())
