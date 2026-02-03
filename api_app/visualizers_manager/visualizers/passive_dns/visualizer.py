from logging import getLogger
from typing import Dict, List

from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.visualizers.passive_dns.analyzer_extractor import (
    extract_circlpdns_reports,
    extract_dnsdb_reports,
    extract_mnemonicpdns_reports,
    extract_otxquery_reports,
    extract_robtex_reports,
    extract_threatminer_reports,
    extract_validin_reports,
)
from api_app.visualizers_manager.visualizers.passive_dns.pdns_table import (
    pdns_table,
    standard_table_columns,
)

logger = getLogger(__name__)


class PassiveDNS(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> List[Dict]:
        raw_pdns_data = []
        raw_pdns_data.extend(extract_otxquery_reports(self.get_analyzer_reports(), self._job))
        raw_pdns_data.extend(extract_threatminer_reports(self.get_analyzer_reports(), self._job))
        raw_pdns_data.extend(extract_validin_reports(self.get_analyzer_reports(), self._job))
        raw_pdns_data.extend(extract_dnsdb_reports(self.get_analyzer_reports(), self._job))
        raw_pdns_data.extend(extract_circlpdns_reports(self.get_analyzer_reports(), self._job))
        raw_pdns_data.extend(extract_robtex_reports(self.get_analyzer_reports(), self._job))
        raw_pdns_data.extend(extract_mnemonicpdns_reports(self.get_analyzer_reports(), self._job))

        page = self.Page(name="Passive DNS")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=pdns_table(raw_pdns_data, standard_table_columns())),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
