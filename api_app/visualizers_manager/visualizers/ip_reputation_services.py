from logging import getLogger
from typing import Dict, List

from api_app.core.choices import Status
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.enums import (
    VisualizableColor,
    VisualizableIcon,
    VisualizableSize,
)

logger = getLogger(__name__)


class IPReputationServices(Visualizer):
    def run(self) -> List[Dict]:
        first_level_elements = []
        second_level_elements = []
        third_level_elements = []

        analyzer_report = self.analyzer_reports().get(
            config__name="VirusTotal_v3_Get_Observable"
        )
        if analyzer_report:
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
                disable=analyzer_report.status != Status.SUCCESS or not hits,
            )
            first_level_elements.append(virustotal_report)

        analyzer_report = self.analyzer_reports().get(config__name="GreyNoiseCommunity")
        if analyzer_report:
            message = analyzer_report.report.get("message", None)
            disabled = analyzer_report.status != Status.SUCCESS or message != "Success"
            classification = analyzer_report.report.get("classification", "")
            if classification == "benign":
                icon = VisualizableIcon.LIKE
                color = VisualizableColor.SUCCESS
            elif classification == "malicious":
                icon = VisualizableIcon.MALWARE
                color = VisualizableColor.DANGER
            else:  # should be "unknown"
                icon = VisualizableIcon.WARNING
                color = VisualizableColor.INFO
            greynoise_report = self.Title(
                self.Base(
                    value="Greynoise",
                    link=analyzer_report.report.get("link", ""),
                    icon=icon,
                ),
                self.Base(value=analyzer_report.report.get("name", ""), color=color),
                disable=disabled,
            )
            first_level_elements.append(greynoise_report)

        analyzer_report = self.analyzer_reports().get(config__name="URLhaus")
        if analyzer_report:
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
        if analyzer_report:
            disabled = (
                analyzer_report.status != Status.SUCCESS
                or analyzer_report.report.get("query_status", None) != "ok"
            )
            data = analyzer_report.report.get("data", {})
            threatfox_report = self.Title(
                self.Base(
                    value="ThreatFox", link=analyzer_report.report.get("link", "")
                ),
                self.Base(
                    value=""
                    if disabled
                    else f"found " f'{data.get("malware_printable", "")}'
                ),
                disable=disabled,
            )
            first_level_elements.append(threatfox_report)

        analyzer_report = self.analyzer_reports().get(config__name="InQuest_REPdb")
        if analyzer_report:
            success = analyzer_report.report.get("success", False)
            data = analyzer_report.report.get("data", [])
            disabled = (
                analyzer_report.status != Status.SUCCESS or not success or not data
            )
            inquest_report = self.Title(
                self.Base(
                    value="InQuest",
                    link=analyzer_report.report.get("link", ""),
                    icon=VisualizableIcon.WARNING,
                ),
                self.Base(value="" if disabled else "found"),
                disable=disabled,
            )
            first_level_elements.append(inquest_report)

        analyzer_report = self.analyzer_reports().get(config__name="AbuseIPDB")
        abuse_categories_report = None
        if analyzer_report:
            data = analyzer_report.report.get("data", [])
            isp = data.get("isp", "")
            usage = data.get("usageType", "")
            disabled = analyzer_report.status != Status.SUCCESS or (
                not isp and not usage
            )
            abuse_report = self.Title(
                self.Base(
                    value="AbuseIPDB Meta",
                    link=analyzer_report.report.get("permalink", ""),
                    icon=VisualizableIcon.INFO,
                ),
                self.Base(value="" if disabled else f"{isp} ({usage})"),
                disable=disabled,
            )
            third_level_elements.append(abuse_report)

            disabled = analyzer_report.status != Status.SUCCESS or not data
            categories_extracted = []
            for c in data.get("reports", []):
                categories_extracted.extend(c.get("categories_human_readable", []))
            categories_extracted = list(set(categories_extracted))
            abuse_categories_report = self.VList(
                name=self.Base(
                    value="AbuseIPDB Categories",
                    icon=VisualizableIcon.ALARM,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[self.Base(c, disable=disabled) for c in categories_extracted],
                open=True,
                max_elements_number=5,
                disable=disabled,
                size=VisualizableSize.S_2,
            )

        analyzer_report = self.analyzer_reports().get(config__name="GreedyBear")
        gb_report = None
        if analyzer_report:
            found = analyzer_report.report.get("found", False)
            disabled = analyzer_report.status != Status.SUCCESS or not found
            ioc = analyzer_report.report.get("ioc", {})
            honeypots = [h for h in ioc.get("general_honeypot", [])]
            if ioc.get("cowrie"):
                honeypots.append("Cowrie")
            if ioc.get("log4j"):
                honeypots.append("Log4Pot")
            gb_report = self.VList(
                name=self.Base(
                    value="GreedyBear Honeypots",
                    icon=VisualizableIcon.WARNING,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[self.Base(h, disable=disabled) for h in honeypots],
                open=True,
                max_elements_number=5,
                disable=disabled,
                size=VisualizableSize.S_2,
            )

        analyzer_report = self.analyzer_reports().get(config__name="Crowdsec")
        if analyzer_report:
            classifications = analyzer_report.report.get("classifications", [])
            sub_classifications = classifications.get("classifications", [])
            false_positives = classifications.get("false_positives", [])
            disabled = analyzer_report.status != Status.SUCCESS or not classifications
            crowdsec_report = self.VList(
                name=self.Base(
                    value="Crowdsec Classifications",
                    icon=VisualizableIcon.INFO,
                    color=VisualizableColor.INFO,
                    disable=disabled,
                ),
                value=[
                    self.Base(c.get("label", ""), disable=disabled)
                    for c in sub_classifications + false_positives
                ],
                open=True,
                max_elements_number=5,
                disable=disabled,
                size=VisualizableSize.S_2,
            )
            second_level_elements.append(crowdsec_report)

            if gb_report:
                second_level_elements.append(gb_report)

            if abuse_categories_report:
                second_level_elements.append(abuse_categories_report)

            behaviors = analyzer_report.report.get("behaviors", [])
            disabled = analyzer_report.status != Status.SUCCESS or not behaviors
            crowdsec_report = self.VList(
                name=self.Base(
                    value="Crowdsec Behaviors",
                    icon=VisualizableIcon.ALARM,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[
                    self.Base(b.get("label", ""), disable=disabled) for b in behaviors
                ],
                open=True,
                max_elements_number=5,
                disable=disabled,
                size=VisualizableSize.S_2,
            )
            second_level_elements.append(crowdsec_report)

        analyzer_report = self.analyzer_reports().get(config__name="OTXQuery")
        if analyzer_report:
            pulses = analyzer_report.report.get("pulses", [])
            disabled = analyzer_report.status != Status.SUCCESS or not pulses
            otx_report = self.VList(
                name=self.Base(
                    value="OTX Alienvault",
                    icon=VisualizableIcon.OTX,
                    color=VisualizableColor.DANGER,
                    disable=disabled,
                ),
                value=[
                    self.Base(
                        value=p.get("name", ""),
                        link=p.get("link", ""),
                        disable=disabled,
                    )
                    for p in pulses
                ],
                open=True,
                max_elements_number=5,
                disable=disabled,
                size=VisualizableSize.S_4,
            )
            second_level_elements.append(otx_report)

        analyzer_report = self.analyzer_reports().get(config__name="FireHol_IPList")
        if analyzer_report:
            found_in_lists = []
            for report, found in analyzer_report.report.items():
                if found:
                    found_in_lists.append(report)
            disabled = analyzer_report.status != Status.SUCCESS or not found_in_lists
            otx_report = self.VList(
                name=self.Base(
                    value="FireHol", icon=VisualizableIcon.FIRE, disable=disabled
                ),
                value=[self.Base(f, disable=disabled) for f in found_in_lists],
                open=True,
                max_elements_number=5,
                disable=disabled,
            )
            third_level_elements.append(otx_report)

        analyzer_report = self.analyzer_reports().get(config__name="TorProject")
        if analyzer_report:
            found = analyzer_report.report.get("found", False)
            tor_report = self.Bool(
                name="Tor Exit Node",
                value=analyzer_report.status == Status.SUCCESS and found,
            )
            third_level_elements.append(tor_report)

        analyzer_report = self.analyzer_reports().get(config__name="TalosReputation")
        if analyzer_report:
            found = analyzer_report.report.get("found", False)
            talos_report = self.Bool(
                name="Talos Reputation",
                value=analyzer_report.status == Status.SUCCESS and found,
            )
            third_level_elements.append(talos_report)

        logger.debug(first_level_elements)
        logger.debug(second_level_elements)
        logger.debug(third_level_elements)

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
