from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class DNS(Visualizer):
    def run(self) -> List[Dict]:
        analyzer_report_list = self.analyzer_reports()
        logger.debug(f"analyzer_reports: {analyzer_report_list}")

        first_level_elements = []
        second_level_elements = []

        for analyzer_report in analyzer_report_list:
            analyzer_name = analyzer_report.config.name
            printable_analyzer_name = analyzer_name.replace("_", " ")
            logger.debug(f"{analyzer_name=}")

            if analyzer_name in [
                "Classic_DNS",
                "CloudFlare_DNS",
                "Google_DNS",
                "DNS0_EU",
                "Quad9_DNS",
            ]:
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
            if analyzer_name in [
                "DNS0_EU_Malicious_Detector",
                "CloudFlare_Malicious_Detector",
                "Quad9_Malicious_Detector",
                "GoogleWebRisk",
                "GoogleSafebrowsing",
            ]:
                second_level_elements.append(
                    self.Bool(
                        name=printable_analyzer_name,
                        value=analyzer_report.report["malicious"],
                    )
                )

        result = [
            self.Level(
                level=1,
                horizontal_list=self.HList(value=first_level_elements),
            ),
            self.Level(
                level=2,
                horizontal_list=self.HList(value=second_level_elements),
            ),
        ]
        final_result = [report.to_dict() for report in result]
        logger.debug(f"{final_result=}")
        return final_result

    @classmethod
    def _monkeypatch(cls):
        from kombu import uuid

        # malicious detector services (1st level)
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="DNS0_EU_Malicious_Detector"),
            job=Job.objects.first(),
            status=AnalyzerReport.Status.SUCCESS,
            report={"observable": "dns.google.com", "malicious": False},
            runtime_configuration={},
            task_id=uuid(),
        )
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="CloudFlare_Malicious_Detector"),
            job=Job.objects.first(),
            status=AnalyzerReport.Status.SUCCESS,
            report={"observable": "dns.google.com", "malicious": False},
            runtime_configuration={},
            task_id=uuid(),
        )
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="Quad9_Malicious_Detector"),
            job=Job.objects.first(),
            status=AnalyzerReport.Status.SUCCESS,
            report={"observable": "dns.google.com", "malicious": False},
            runtime_configuration={},
            task_id=uuid(),
        )
        # classic DNS resolution (2nd level)
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="Classic_DNS"),
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
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="CloudFlare_DNS"),
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
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="Google_DNS"),
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
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="DNS0_EU"),
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
        AnalyzerReport.objects.create(
            config=AnalyzerConfig.objects.get(name="Quad9_DNS"),
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
