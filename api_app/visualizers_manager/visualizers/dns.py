from logging import getLogger
from typing import Dict, List

# ignore flake line too long in imports
from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.cloudflare_malicious_detector import (  # noqa: E501
    CloudFlareMaliciousDetector,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.dns0_eu_malicious_detector import (  # noqa: E501
    DNS0EUMaliciousDetector,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.google_webrisk import (  # noqa: E501
    WebRisk,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.googlesf import (  # noqa: E501
    GoogleSF,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_malicious_detectors.quad9_malicious_detector import (  # noqa: E501
    Quad9MaliciousDetector,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.classic_dns_resolver import (  # noqa: E501
    ClassicDNSResolver,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.cloudflare_dns_resolver import (  # noqa: E501
    CloudFlareDNSResolver,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.dns0_eu_resolver import (  # noqa: E501
    DNS0EUResolver,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.google_dns_resolver import (  # noqa: E501
    GoogleDNSResolver,
)
from api_app.analyzers_manager.observable_analyzers.dns.dns_resolvers.quad9_dns_resolver import (  # noqa: E501
    Quad9DNSResolver,
)
from api_app.choices import ObservableClassification
from api_app.models import Job
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class DNS(Visualizer):
    @classmethod
    @property
    def first_level_analyzers(cls) -> List[str]:
        return [  # noqa
            ClassicDNSResolver.python_module,
            CloudFlareDNSResolver.python_module,
            GoogleDNSResolver.python_module,
            DNS0EUResolver.python_module,
            Quad9DNSResolver.python_module,
        ]

    @classmethod
    @property
    def second_level_analyzers(cls) -> List[str]:
        return [  # noqa
            CloudFlareMaliciousDetector.python_module,
            GoogleSF.python_module,
            WebRisk.python_module,
            DNS0EUMaliciousDetector.python_module,
            Quad9MaliciousDetector.python_module,
        ]

    def run(self) -> List[Dict]:

        first_level_elements = []
        second_level_elements = []

        for analyzer_report in self.analyzer_reports():
            printable_analyzer_name = analyzer_report.config.name.replace("_", " ")
            logger.debug(f"{printable_analyzer_name=}")
            logger.debug(f"{analyzer_report.config.python_complete_path=}")
            logger.debug(f"{analyzer_report=}")
            if "dns.dns_resolvers" in analyzer_report.config.python_complete_path:
                first_level_elements.append(
                    self.VList(
                        name=self.Base(
                            value=f"{printable_analyzer_name} "
                            f"({len(analyzer_report.report['resolutions'])})"
                        ),
                        value=[
                            self.Base(
                                value=dns_resolution["data"]
                                if self._job.observable_classification
                                == ObservableClassification.DOMAIN
                                else dns_resolution
                            )
                            for dns_resolution in analyzer_report.report["resolutions"]
                        ],
                        open=True,
                    )
                )
            else:
                second_level_elements.append(
                    self.Bool(
                        name=printable_analyzer_name,
                        value=analyzer_report.report["malicious"],
                    )
                )

        page = self.Page()
        page.add_level(
            level=1,
            horizontal_list=self.HList(value=first_level_elements),
        )
        page.add_level(
            level=2,
            horizontal_list=self.HList(value=second_level_elements),
        )
        logger.debug(f"levels: {page.to_dict()}")
        return [page.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        from kombu import uuid

        # malicious detector services (1st level)

        for python_module in cls.first_level_analyzers:
            report = AnalyzerReport(
                config=AnalyzerConfig.objects.get(python_module=python_module),
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
                task_id=uuid(),
            )
            report.full_clean()
            report.save()

        # classic DNS resolution (2nd level)
        for python_module in cls.second_level_analyzers:
            report = AnalyzerReport(
                config=AnalyzerConfig.objects.get(python_module=python_module),
                job=Job.objects.first(),
                status=AnalyzerReport.Status.SUCCESS,
                report={"observable": "dns.google.com", "malicious": False},
                task_id=uuid(),
            )
            report.full_clean()
            report.save()

        patches = []
        return super()._monkeypatch(patches=patches)
