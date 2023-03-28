from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class DNS(Visualizer):
    @classmethod
    @property
    def first_level_analyzers(cls) -> List[str]:
        return [
            "Classic_DNS",
            "CloudFlare_DNS",
            "Google_DNS",
            "DNS0_EU",
            "Quad9_DNS",
        ]

    @classmethod
    @property
    def second_level_analyzers(cls) -> List[str]:
        return [
            "DNS0_EU_Malicious_Detector",
            "CloudFlare_Malicious_Detector",
            "Quad9_Malicious_Detector",
            "GoogleWebRisk",
            "GoogleSafebrowsing",
        ]

    def run(self) -> List[Dict]:
        analyzer_report_list = self.analyzer_reports().filter(
            config__name__in=self.first_level_analyzers + self.second_level_analyzers
        )
        logger.debug(f"analyzer_reports: {analyzer_report_list}")

        first_level_elements = []
        second_level_elements = []

        for analyzer_report in analyzer_report_list:
            analyzer_name = analyzer_report.config.name
            printable_analyzer_name = analyzer_name.replace("_", " ")
            logger.debug(f"{analyzer_name=}")

            if analyzer_name in self.first_level_analyzers:
                first_level_elements.append(
                    self.VList(
                        name=f"{printable_analyzer_name} "
                        f"({len(analyzer_report.report['resolutions'])})",
                        value=[
                            self.Base(dns_resolution["data"])
                            for dns_resolution in analyzer_report.report["resolutions"]
                        ],
                        open=True,
                    )
                )
            if analyzer_name in self.second_level_analyzers:
                second_level_elements.append(
                    self.Bool(
                        name=printable_analyzer_name,
                        value=analyzer_report.report["malicious"],
                    )
                )
        levels = self.Level()
        levels.add_level(
            level=1,
            horizontal_list=self.HList(value=first_level_elements),
        )
        levels.add_level(
            level=2,
            horizontal_list=self.HList(value=second_level_elements),
        )
        logger.debug(f"{levels=}")
        return levels.to_dict()

    @classmethod
    def _monkeypatch(cls):
        from kombu import uuid

        # malicious detector services (1st level)

        for analyzer in cls.first_level_analyzers:
            AnalyzerReport.objects.create(
                config=AnalyzerConfig.objects.get(name=analyzer),
                job=Job.objects.first(),
                status=AnalyzerReport.Status.SUCCESS,
                report={"observable": "dns.google.com", "malicious": False},
                runtime_configuration={},
                task_id=uuid(),
            )

        # classic DNS resolution (2nd level)
        for analyzer in cls.second_level_analyzers:
            AnalyzerReport.objects.create(
                config=AnalyzerConfig.objects.get(name=analyzer),
                job=Job.objects.first(),
                status=AnalyzerReport.Status.SUCCESS,
                report={
                    "observable": "dns.google.com",
                    "resolutions": [
                        {
                            "TTL": 456,
                            "data": "8.8.8.8",
                            "name": "dns.google.com",
                            "type": 1,
                        },
                        {
                            "TTL": 456,
                            "data": "8.8.4.4",
                            "name": "dns.google.com",
                            "type": 1,
                        },
                    ],
                },
                runtime_configuration={"query_type": "A"},
                task_id=uuid(),
            )

        patches = []
        return super()._monkeypatch(patches=patches)
