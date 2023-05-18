from logging import getLogger
from typing import Dict, List

from api_app.core.choices import Status
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.enums import VisualizableIcon

logger = getLogger(__name__)


class DomainReputationServices(Visualizer):
    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []

        for analyzer_report in self.analyzer_reports():
            if (
                "Malicious_Detector" in analyzer_report.config.name
                or analyzer_report.config.name == "GoogleSafebrowsing"
            ):
                printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
                logger.debug(f"{printable_analyzer_name=}")
                logger.debug(f"{analyzer_report.config.python_complete_path=}")
                logger.debug(f"{analyzer_report=}")
                third_level_elements.append(
                    self.Bool(
                        name=printable_analyzer_name,
                        value=analyzer_report.report["malicious"],
                    )
                )

        analyzer_report = self.analyzer_reports().get(
            config__name="VirusTotal_v3_Get_Observable"
        )
        hits = (
            analyzer_report.report.get("data", {})
            .get("total_votes", {})
            .get("malicious", 0)
        )
        virustotal_report = self.Title(
            self.Base(
                value="VirusTotal",
                link=analyzer_report.report["link"],
                icon=VisualizableIcon.VIRUSTotal,
            ),
            self.Base(value=f"Engine Hits: {hits}"),
            disable=analyzer_report.status != Status.SUCCESS,
        )
        first_level_elements.append(virustotal_report)

        analyzer_report = self.analyzer_reports().get(config__name="URLhaus")
        disabled = (
            analyzer_report.status != Status.SUCCESS
            or analyzer_report.report.get("query_status", None) != "ok"
        )
        urlhaus_report = self.Title(
            self.Base(
                value="URLhaus",
                link=analyzer_report.report.get("urlhaus_reference", ""),
                icon=VisualizableIcon.URLHAUS,
            ),
            self.Base(
                value=""
                if disabled
                else f'found {analyzer_report.report.get("urlhaus_status", "")}'
            ),
            disable=disabled,
        )
        first_level_elements.append(urlhaus_report)

        analyzer_report = self.analyzer_reports().get(config__name="ThreatFox")
        disabled = (
            analyzer_report.status != Status.SUCCESS
            or analyzer_report.report.get("query_status", None) != "ok"
        )
        threatfox_report = self.Title(
            self.Base(value="ThreatFox", link=analyzer_report.report.get("link", "")),
            self.Base(
                value=""
                if disabled
                else f"found "
                f'{analyzer_report.report.get("data", {}).get("malware_printable", "")}'
            ),
            disable=disabled,
        )
        first_level_elements.append(threatfox_report)

        analyzer_report = self.analyzer_reports().get(config__name="Phishtank")
        results = analyzer_report.report.get("results", {})
        in_database = results.get("in_database", False)
        disabled = analyzer_report.status != Status.SUCCESS or not in_database
        phishtank_report = self.Title(
            self.Base(
                value="Phishtank",
                link=results.get("phish_detail_page", ""),
                icon=VisualizableIcon.PHISHING,
            ),
            self.Base(value="" if disabled else "found"),
            disable=disabled,
        )
        second_level_elements.append(phishtank_report)

        analyzer_report = self.analyzer_reports().get(config__name="PhishingArmy")
        found = analyzer_report.report.get("found", False)
        disabled = analyzer_report.status != Status.SUCCESS or not found
        phishtank_report = self.Title(
            self.Base(
                value="PhishingArmy",
                link=analyzer_report.report.get("link", ""),
                icon=VisualizableIcon.PHISHING,
            ),
            self.Base(value="" if disabled else "found"),
            disable=disabled,
        )
        second_level_elements.append(phishtank_report)

        analyzer_report = self.analyzer_reports().get(config__name="InQuest_REPdb")
        success = analyzer_report.report.get("success", False)
        data = analyzer_report.report.get("data", [])
        disabled = analyzer_report.status != Status.SUCCESS or not success or not data
        inquest_report = self.Title(
            self.Base(
                value="InQuest",
                link=analyzer_report.report.get("link", ""),
                icon=VisualizableIcon.WARNING,
            ),
            self.Base(value="" if disabled else "found"),
            disable=disabled,
        )
        second_level_elements.append(inquest_report)

        analyzer_report = self.analyzer_reports().get(config__name="OTXQuery")
        pulses = analyzer_report.report.get("pulses", [])
        disabled = analyzer_report.status != Status.SUCCESS or not pulses
        otx_report = self.VList(
            name=self.Base(value="OTXQuery", icon=VisualizableIcon.OTX),
            value=[p.get("link", "") for p in pulses],
            open=True,
            max_elements_number=5,
            disable=disabled,
        )
        second_level_elements.append(otx_report)

        page = self.Page(name="Reputation")
        page.add_level(
            level=1,
            horizontal_list=self.HList(value=first_level_elements),
        )
        page.add_level(
            level=2,
            horizontal_list=self.HList(value=second_level_elements),
        )
        page.add_level(
            level=3,
            horizontal_list=self.HList(value=third_level_elements),
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        patches = []
        return super()._monkeypatch(patches=patches)
