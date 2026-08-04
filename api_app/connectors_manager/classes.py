# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import abc
import logging
import typing
from typing import List, Optional, Type

from django.conf import settings
from django.utils.functional import cached_property

from api_app import helpers
from api_app.choices import Classification
from api_app.decorators import classproperty

from ..choices import PythonModuleBasePaths, ReportStatus
from ..classes import Plugin
from .exceptions import ConnectorConfigurationException, ConnectorRunException
from .models import ConnectorConfig, ConnectorReport

logger = logging.getLogger(__name__)


class Connector(Plugin, metaclass=abc.ABCMeta):
    """
    Abstract class for all Connectors.
    Inherit from this branch when defining a connector.
    Need to overrwrite `set_params(self, params: dict)`
     and `run(self)` functions.
    """

    @classproperty
    def python_base_path(cls):
        return PythonModuleBasePaths.Connector.value

    @classproperty
    def report_model(cls) -> Type[ConnectorReport]:
        return ConnectorReport

    @classproperty
    def config_model(cls) -> Type[ConnectorConfig]:
        return ConnectorConfig

    def get_exceptions_to_catch(self) -> list:
        return [
            ConnectorConfigurationException,
            ConnectorRunException,
        ]

    def before_run(self):
        super().before_run()
        logger.info(f"STARTED connector: {self.__repr__()}")
        self._config: ConnectorConfig
        # an analyzer can start
        # if the run_on_failure flag is set
        # if there are no analyzer_reports
        # it all the analyzer_reports are not failed
        if (
            self._config.run_on_failure
            or not self._job.analyzerreports.count()
            or not self._job.analyzerreports.filter(status=ReportStatus.FAILED.value).exists()
        ):
            logger.info(
                f"Running connector {self.__class__.__name__} "
                f"even if job status is {self._job.status} because"
                "run on failure is set"
            )
        else:
            raise ConnectorRunException(
                f"An analyzer has failed, unable to run connector {self.__class__.__name__}"
            )

    def after_run(self):
        super().after_run()
        logger.info(f"FINISHED connector: {self.__repr__()}")


class CTIConnector(Connector):
    """
    Base class for Cyber Threat Intelligence connectors (MISP, OpenCTI, YETI).

    Provides standardized, reusable properties for:
    - Observable metadata extraction (name, value, classification, hash type, IP version)
    - Job context (analysis URL, tag labels, analyzer names)
    - Data-model enrichment (evaluation verdict, malware family, kill chain phase,
      reliability score, related threats, etc.)

    Subclasses should inherit from this class.
    Enrichment properties are opt-in: each subclass decides which fields to include
    in its platform-specific payload.
    """

    @abc.abstractmethod
    def run(self) -> dict:
        raise NotImplementedError()

    # ── Observable Metadata ──────────────────────────────────────

    @property
    def observable_name(self) -> str:
        return self._job.analyzable.name

    @property
    def observable_value(self) -> str:
        if self._job.is_sample:
            return self._job.analyzable.md5
        return self._job.analyzable.name

    @property
    def classification(self) -> str:
        if self._job.is_sample:
            return Classification.FILE
        return self._job.analyzable.classification

    @property
    def hash_type(self) -> Optional[str]:
        if not self._job.is_sample and self._job.analyzable.classification == Classification.HASH:
            return helpers.get_hash_type(self._job.analyzable.name)
        return None

    @property
    def ip_version(self) -> Optional[int]:
        if not self._job.is_sample and self._job.analyzable.classification == Classification.IP:
            return helpers.get_ip_version(self._job.analyzable.name)
        return None

    @property
    def analysis_url(self) -> str:
        return f"{settings.WEB_CLIENT_URL}/jobs/{self.job_id}"

    @property
    def tag_labels(self) -> List[str]:
        return list(self._job.tags.all().values_list("label", flat=True))

    @property
    def analyzer_names(self) -> List[str]:
        return list(self._job.analyzers_to_execute.all().values_list("name", flat=True))

    # Data-Model Enrichment

    @cached_property
    def _merged_data_model(self) -> typing.Any:
        # Returns the merged data model from the
        # engine step, or None if unavailable

        return getattr(self._job, "data_model", None)

    @property
    def has_data_model(self) -> bool:
        return self._merged_data_model is not None

    @property
    def evaluation(self) -> Optional[str]:
        # Verdict: trusted, malicious, or None.
        dm = self._merged_data_model
        return dm.evaluation if dm else None

    @property
    def malware_family(self) -> Optional[str]:
        dm = self._merged_data_model
        return dm.malware_family if dm else None

    @property
    def kill_chain_phase(self) -> Optional[str]:
        dm = self._merged_data_model
        return dm.kill_chain_phase if dm else None

    @property
    def reliability(self) -> Optional[int]:
        dm = self._merged_data_model
        return dm.reliability if dm else None

    @property
    def related_threats(self) -> List[str]:
        dm = self._merged_data_model
        return list(dm.related_threats) if dm and dm.related_threats else []

    @property
    def data_model_tags(self) -> List[str]:
        dm = self._merged_data_model
        return list(dm.tags) if dm and dm.tags else []

    @property
    def external_references(self) -> List[str]:
        dm = self._merged_data_model
        return list(dm.external_references) if dm and dm.external_references else []

    def get_enrichment_summary(self) -> dict:
        """
        Returns a dict summarizing all available enrichment fields.
        Only includes fields that have non-None/non-empty values.
        Useful for connectors that want to bulk-attach enrichment metadata.
        """
        summary = {}
        fields = {
            "evaluation": self.evaluation,
            "malware_family": self.malware_family,
            "kill_chain_phase": self.kill_chain_phase,
            "reliability": self.reliability,
            "related_threats": self.related_threats,
            "data_model_tags": self.data_model_tags,
            "external_references": self.external_references,
        }
        for key, value in fields.items():
            if value:
                summary[key] = value
        return summary
