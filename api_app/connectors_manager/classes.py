from abc import abstractmethod
import logging

from ..exceptions import (
    ConnectorConfigurationException,
    ConnectorRunException,
    ConnectorRunNotImplemented,
)
from ..analyzers_manager.classes import BaseAnalyzerMixin
from api_app.models import Job


logger = logging.getLogger(__name__)


class BaseConnectorMixin(BaseAnalyzerMixin):
    """
    Abstract Base class for Connectors.
    Never inherit from this branch,
    always use Connector class.
    """

    connector_name: str

    @abstractmethod
    def run(self):
        raise ConnectorRunNotImplemented(self.connector_name)

    def get_report_object(self):
        return Job.init_connector_report(self.connector_name, self.job_id)

    def get_error_message(self, err, is_base_err=False):
        return (
            f"job_id:{self.job_id}, connector: '{self.connector_name}'."
            f" {'Unexpected error' if is_base_err else 'Connector error'}: '{err}'"
        )

    def get_exceptions_to_catch(self):
        return (
            ConnectorConfigurationException,
            ConnectorRunException,
        )

    def __init__(self, connector_name, job_id, additional_config_params):
        self.connector_name = connector_name
        super().__init__("", job_id, additional_config_params)

    def __repr__(self):
        return f"({self.connector_name}, job_id: #{self.job_id})"


class Connector(BaseConnectorMixin):
    """
    Abstract class for all Connectors.
    Inherit from this branch when defining a connector.
    Need to overrwrite `set_config(self, additional_config_params)`
     and `run(self)` functions.
    """

    def __init__(
        self,
        connector_name,
        job_id,
        additional_config_params,
    ):
        super().__init__(connector_name, job_id, additional_config_params)

    def before_run(self):
        logger.info(f"STARTED connector: {self.__repr__()}")

    def after_run(self):
        logger.info(f"FINISHED connector: {self.__repr__()}")
