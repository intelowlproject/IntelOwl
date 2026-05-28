# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock

from api_app.connectors_manager.exceptions import ConnectorRunException

logger = logging.getLogger(__name__)


class BaseConnectorTest(TestCase):
    connector_class: type = None
    suppress_connector_logs = True

    def setUp(self):
        super().setUp()
        logger.info(f"Setting up test environment for {self.__class__.__name__}")

        if self.suppress_connector_logs and self.connector_class:
            connector_module = self.connector_class.__module__
            logging.getLogger(connector_module).setLevel(logging.CRITICAL)
            logging.getLogger("api_app.connectors_manager").setLevel(logging.WARNING)

    def tearDown(self):
        super().tearDown()
        logger.info(f"Tearing down test environment for {self.__class__.__name__}")

        if self.suppress_connector_logs and self.connector_class:
            connector_module = self.connector_class.__module__
            logging.getLogger(connector_module).setLevel(logging.NOTSET)
            logging.getLogger("api_app.connectors_manager").setLevel(logging.NOTSET)

    @classmethod
    def get_extra_config(cls) -> dict:
        """
        Subclasses can override this to provide additional runtime configuration
        specific to their connector (e.g., API keys, URLs, retry counts, etc.).
        """
        return {}

    @classmethod
    def get_mocked_response(cls):
        """
        Subclasses override this to define expected mocked output.
        """
        raise NotImplementedError("Subclasses must implement get_mocked_response()")

    @classmethod
    def _apply_patches(cls, patches):
        if patches is None:
            return ExitStack()

        if hasattr(patches, "__enter__") and hasattr(patches, "__exit__"):
            return patches

        if isinstance(patches, (list, tuple)):
            stack = ExitStack()
            for patch_obj in patches:
                stack.enter_context(patch_obj)
            return stack

        return patches

    # different connectors may require different job setups so
    # we create a mock job here that can be customized as needed
    # pylint: disable=no-self-use
    def _create_mock_job(self, observable_name, observable_type):
        mock_tlp_enum = SimpleNamespace()
        mock_tlp_enum.CLEAR = SimpleNamespace(value="clear")
        mock_tlp_enum.GREEN = SimpleNamespace(value="green")
        mock_tlp_enum.AMBER = SimpleNamespace(value="amber")
        mock_tlp_enum.RED = SimpleNamespace(value="red")

        mock_analyzable = SimpleNamespace()
        mock_analyzable.name = observable_name
        mock_analyzable.classification = observable_type

        mock_job = SimpleNamespace()
        mock_job.analyzable = mock_analyzable
        mock_job.pk = 51

        mock_job.tlp = "clear"
        mock_job.TLP = mock_tlp_enum
        mock_job.user = ""
        mock_job.is_sample = False

        return mock_job

    def _setup_connector(self):
        logger.info(f"Setting up connector {self.connector_class.__name__} for testing")
        mock_config = MagicMock()

        # we have already handled connector_class being None in
        # the test method, so we can safely assume it's set here
        # pylint: disable=not-callable
        connector = self.connector_class(mock_config)
        connector._job = self._create_mock_job("1.1.1.1", "ip")

        for key, value in self.get_extra_config().items():
            setattr(connector, key, value)

        return connector

    def test_connector_run_execution(self):
        if self.connector_class is None:
            self.skipTest(f"{self.__class__.__name__} does not specify a connector_class")

        logger.info(f"Starting generic connector test for {self.connector_class.__name__}")

        connector = self._setup_connector()
        patches = self.get_mocked_response()
        with self._apply_patches(patches):
            try:
                response = connector.run()
                self.assertIsInstance(
                    response,
                    (dict, list),
                    f"Connector response should be a dictionary or a list, got {type(response)}",
                )
                self.assertTrue(response, "Connector response should not be empty")
                logger.info(f"Connector run successful for {self.connector_class.__name__}")

            except ConnectorRunException as e:
                logger.error(f"ConnectorRunException for {self.connector_class.__name__}: {e}")
                self.fail(
                    f"{self.__class__.__name__}: ConnectorRunException for {self.connector_class.__name__}: {e}"
                )

            except Exception as e:
                logger.exception(f"Unexpected exception for {self.connector_class.__name__}")
                self.fail(
                    f"{self.__class__.__name__}: Unexpected exception "
                    f"for {self.connector_class.__name__}: {type(e).__name__}: {e}"
                )
