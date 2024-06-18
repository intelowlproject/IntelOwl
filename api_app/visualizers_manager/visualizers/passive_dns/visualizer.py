from logging import getLogger
from typing import Dict, List

from api_app.visualizers_manager.classes import VisualizableObject, Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import VisualizableTableColumnSize
from api_app.visualizers_manager.visualizers.passive_dns.analyzer_extractor import (
    extract_circlpdns_reports,
    extract_dnsdb_reports,
    extract_mnemonicpdns_reports,
    extract_otxquery_reports,
    extract_robtex_reports,
    extract_threatminer_reports,
    extract_validin_reports,
)
from api_app.visualizers_manager.visualizers.passive_dns.visualize_report import (
    visualize_report,
)

logger = getLogger(__name__)


class PassiveDNS(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    @visualizable_error_handler_with_params("pdns_table")
    def _pdns_table_ui(self, reports) -> VisualizableObject:
        visualizable_reports = []
        for report in reports:
            visualizable_reports.append(visualize_report(report))

        columns = [
            Visualizer.TableColumn(
                name="last_view",
                max_width=VisualizableTableColumnSize.S_100,
                description="""The last time that the unique tuple"
                 (rrname, rrtype, rdata) record has been seen by the passive DNS.""",
            ),
            Visualizer.TableColumn(
                name="first_view",
                max_width=VisualizableTableColumnSize.S_100,
                description="""The first time that the record / unique tuple
                 (rrname, rrtype, rdata) has been seen by the passive DNS.""",
            ),
            Visualizer.TableColumn(
                name="rrname",
                max_width=VisualizableTableColumnSize.S_300,
                disable_sort_by=True,
                description="Name of the queried resource.",
            ),
            Visualizer.TableColumn(
                name="rrtype",
                max_width=VisualizableTableColumnSize.S_50,
                disable_sort_by=True,
                description="Record type as seen by the passive DNS.",
            ),
            Visualizer.TableColumn(
                name="rdata",
                max_width=VisualizableTableColumnSize.S_300,
                disable_sort_by=True,
                description="Resource records of the queried resource.",
            ),
            Visualizer.TableColumn(
                name="source",
                max_width=VisualizableTableColumnSize.S_200,
                disable_sort_by=True,
            ),
        ]

        return [
            self.Table(
                data=visualizable_reports,
                columns=columns,
                size=self.Size.S_ALL,
                page_size=10,
                sort_by_id="last_view",
                sort_by_desc=True,
            )
        ]

    def run(self) -> List[Dict]:
        reports_data = []
        reports_data.extend(
            extract_otxquery_reports(self.analyzer_reports(), self._job)
        )
        reports_data.extend(
            extract_threatminer_reports(self.analyzer_reports(), self._job)
        )
        reports_data.extend(extract_validin_reports(self.analyzer_reports(), self._job))
        reports_data.extend(extract_dnsdb_reports(self.analyzer_reports(), self._job))
        reports_data.extend(
            extract_circlpdns_reports(self.analyzer_reports(), self._job)
        )
        reports_data.extend(extract_robtex_reports(self.analyzer_reports(), self._job))
        reports_data.extend(
            extract_mnemonicpdns_reports(self.analyzer_reports(), self._job)
        )

        page = self.Page(name="Passive DNS")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=self._pdns_table_ui(reports_data)),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
