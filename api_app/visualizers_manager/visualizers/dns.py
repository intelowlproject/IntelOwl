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
        return [
            cls.__generate_classpath(ClassicDNSResolver),
            cls.__generate_classpath(CloudFlareDNSResolver),
            cls.__generate_classpath(GoogleDNSResolver),
            cls.__generate_classpath(DNS0EUResolver),
            cls.__generate_classpath(Quad9DNSResolver),
        ]

    @classmethod
    @property
    def second_level_analyzers(cls) -> List[str]:
        return [
            cls.__generate_classpath(CloudFlareMaliciousDetector),
            cls.__generate_classpath(GoogleSF),
            cls.__generate_classpath(WebRisk),
            cls.__generate_classpath(DNS0EUMaliciousDetector),
            cls.__generate_classpath(Quad9MaliciousDetector),
        ]

    def run(self) -> List[Dict]:
        required_analyzer_list = self._config.analyzers.all()
        logger.debug(f"{required_analyzer_list=}")

        first_level_elements = []
        second_level_elements = []

        for required_analyzer in required_analyzer_list:
            printable_analyzer_name = required_analyzer.name.replace("_", " ")
            analyzer_report = self.analyzer_reports().get(
                config__name=required_analyzer.name
            )
            logger.debug(f"{printable_analyzer_name=}")
            logger.debug(f"{required_analyzer.python_complete_path=}")
            logger.debug(f"{analyzer_report=}")
            if "dns.dns_resolvers" in required_analyzer.python_complete_path:
                first_level_elements.append(
                    self.VList(
                        name=f"{printable_analyzer_name} "
                        f"({len(analyzer_report.report['resolutions'])})",
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

        levels = self.Level()
        levels.add_level(
            level=1,
            horizontal_list=self.HList(value=first_level_elements),
        )
        levels.add_level(
            level=2,
            horizontal_list=self.HList(value=second_level_elements),
        )
        logger.debug(f"levels: {levels.to_dict()}")
        return levels.to_dict()

    @classmethod
    def __generate_classpath(cls, class_):
        return f"{class_.__module__}.{class_.__name__}"

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
