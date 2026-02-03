from logging import getLogger
from typing import Dict, List

from django.db.models import Q

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import ReportStatus
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)
from api_app.visualizers_manager.enums import VisualizableIcon

logger = getLogger(__name__)


class DomainReputationServices(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    @visualizable_error_handler_with_params("VirusTotal")
    def _vt3(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="VirusTotal_v3_Get_Observable")
        except AnalyzerReport.DoesNotExist:
            logger.warning("VirusTotal_v3_Get_Observable report does not exist")
            virustotal_report = self.Title(
                self.Base(
                    value="VirusTotal",
                    link="",
                    icon=VisualizableIcon.VIRUSTotal,
                ),
                self.Base(value="Engine Hits: Unknown"),
                disable=True,
            )
            return virustotal_report
        else:
            hits = (
                analyzer_report.report.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )
            virustotal_report = self.Title(
                self.Base(
                    value="VirusTotal",
                    link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.VIRUSTotal,
                ),
                self.Base(value=f"Engine Hits: {hits}"),
                disable=analyzer_report.status != ReportStatus.SUCCESS or not hits,
            )
            return virustotal_report

    @visualizable_error_handler_with_params("URLhaus")
    def _urlhaus(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="URLhaus")
        except AnalyzerReport.DoesNotExist:
            logger.warning("URLhaus report does not exist")
        else:
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or analyzer_report.report.get("query_status", None) != "ok"
            )
            urlhaus_report = self.Title(
                self.Base(
                    value="URLhaus",
                    link=analyzer_report.report.get("urlhaus_reference", ""),
                    icon=VisualizableIcon.URLHAUS,
                ),
                self.Base(
                    value=("" if disabled else f"found {analyzer_report.report.get('urlhaus_status', '')}")
                ),
                disable=disabled,
            )
            return urlhaus_report

    @visualizable_error_handler_with_params("ThreatFox")
    def _threatfox(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="ThreatFox")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Threatfox report does not exist")
        else:
            disabled = (
                analyzer_report.status != ReportStatus.SUCCESS
                or analyzer_report.report.get("query_status", None) != "ok"
            )
            data = analyzer_report.report.get("data", [])
            malware_printable = ""
            if data and isinstance(data, list):
                malware_printable = data[0].get("malware_printable", "")
            threatfox_report = self.Title(
                self.Base(
                    value="ThreatFox",
                    link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.URLHAUS,
                ),
                self.Base(value="" if disabled else f"found {malware_printable}"),
                disable=disabled,
            )
            return threatfox_report

    @visualizable_error_handler_with_params("Tranco")
    def _tranco(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Tranco")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Tranco report does not exist")
        else:
            ranks = analyzer_report.report.get("ranks", [])
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not ranks
            rank = ""
            if ranks and isinstance(ranks, list):
                rank = ranks[0].get("rank", "")
            tranco_report = self.Title(
                self.Base(
                    value="Tranco Rank",
                    link="https://tranco-list.eu/",
                ),
                self.Base(value="" if disabled else rank),
                disable=disabled,
            )
            return tranco_report

    @visualizable_error_handler_with_params("Phishtank")
    def _phishtank(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="Phishtank")
        except AnalyzerReport.DoesNotExist:
            logger.warning("Phishtank report does not exist")
        else:
            results = analyzer_report.report.get("results", {})
            in_database = results.get("in_database", False)
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not in_database
            phishtank_report = self.Title(
                self.Base(
                    value="Phishtank",
                    link=results.get("phish_detail_page", ""),
                    icon=VisualizableIcon.PHISHING,
                ),
                self.Base(value="" if disabled else "found"),
                disable=disabled,
            )
            return phishtank_report

    @visualizable_error_handler_with_params("PhishingArmy")
    def _phishing_army(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="PhishingArmy")
        except AnalyzerReport.DoesNotExist:
            logger.warning("PhishingArmy report does not exist")
        else:
            found = analyzer_report.report.get("found", False)
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not found
            phishtank_report = self.Title(
                self.Base(
                    value="PhishingArmy",
                    link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.PHISHING,
                ),
                self.Base(value="" if disabled else "found"),
                disable=disabled,
            )
            return phishtank_report

    @visualizable_error_handler_with_params("InQuest")
    def _inquest_repdb(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="InQuest_REPdb")
        except AnalyzerReport.DoesNotExist:
            logger.warning("InQuest_REPdb report does not exist")
        else:
            success = analyzer_report.report.get("success", False)
            data = analyzer_report.report.get("data", [])
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not success or not data
            inquest_report = self.Title(
                self.Base(
                    value="InQuest",
                    link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.WARNING,
                ),
                self.Base(value="" if disabled else "found"),
                disable=disabled,
            )
            return inquest_report

    @visualizable_error_handler_with_params("OTX Alienvault")
    def _otxquery(self):
        try:
            analyzer_report = self.get_analyzer_reports().get(config__name="OTXQuery")
        except AnalyzerReport.DoesNotExist:
            logger.warning("OTXQuery report does not exist")
        else:
            pulses = analyzer_report.report.get("pulses", [])
            disabled = analyzer_report.status != ReportStatus.SUCCESS or not pulses
            otx_report = self.VList(
                name=self.Base(value="OTX Alienvault", icon=VisualizableIcon.OTX, disable=disabled),
                value=[
                    self.Base(
                        value=p.get("name", ""),
                        link=p.get("link", ""),
                        disable=disabled,
                    )
                    for p in pulses
                ],
                start_open=True,
                max_elements_number=5,
                report=analyzer_report,
                disable=disabled,
            )
            return otx_report

    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []

        for analyzer_report in self.get_analyzer_reports().filter(
            Q(config__name__endswith="Malicious_Detector") | Q(config__name="GoogleSafebrowsing")
        ):
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            third_level_elements.append(
                self.Bool(
                    value=printable_analyzer_name,
                    disable=not analyzer_report.report.get("malicious"),
                )
            )

        first_level_elements.append(self._vt3())

        first_level_elements.append(self._urlhaus())

        first_level_elements.append(self._threatfox())

        first_level_elements.append(self._tranco())

        second_level_elements.append(self._phishtank())

        second_level_elements.append(self._phishing_army())

        second_level_elements.append(self._inquest_repdb())

        second_level_elements.append(self._otxquery())

        page = self.Page(name="Reputation")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=first_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_5,
                horizontal_list=self.HList(value=second_level_elements),
            )
        )
        page.add_level(
            self.Level(
                position=3,
                size=self.LevelSize.S_6,
                horizontal_list=self.HList(value=third_level_elements),
            )
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
