import json
import logging
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import TestCase

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig

logger = logging.getLogger(__name__)


class BaseAnalyzerTest(TestCase):
    analyzer_class = None
    suppress_analyzer_logs = True

    def setUp(self):
        super().setUp()
        logger.info(f"Setting up test environment for {self.__class__.__name__}")

        if self.suppress_analyzer_logs and self.analyzer_class:
            analyzer_module = self.analyzer_class.__module__
            logging.getLogger(analyzer_module).setLevel(logging.CRITICAL)
            logging.getLogger("api_app.analyzers_manager").setLevel(logging.WARNING)

    def tearDown(self):
        super().tearDown()
        logger.info(f"Tearing down test environment for {self.__class__.__name__}")

        if self.suppress_analyzer_logs and self.analyzer_class:
            analyzer_module = self.analyzer_class.__module__
            logging.getLogger(analyzer_module).setLevel(logging.NOTSET)
            logging.getLogger("api_app.analyzers_manager").setLevel(logging.NOTSET)

    @classmethod
    def get_sample_observable(cls, observable_type):
        return {
            "domain": "example.com",
            "ip": "8.8.8.8",
            "url": "https://example.com",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "generic": "test@intelowl.com",
        }.get(observable_type, "test")

    @classmethod
    def get_extra_config(cls) -> dict:
        """
        Subclasses can override this to provide additional runtime configuration
        specific to their analyzer (e.g., API keys, URLs, retry counts, etc.).
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

    @staticmethod
    def _create_mock_analyzer_job(observable_name, observable_type):
        mock_tlp_enum = SimpleNamespace()
        mock_tlp_enum.CLEAR = SimpleNamespace(value="clear")
        mock_tlp_enum.GREEN = SimpleNamespace(value="green")
        mock_tlp_enum.AMBER = SimpleNamespace(value="amber")
        mock_tlp_enum.RED = SimpleNamespace(value="red")

        mock_job = SimpleNamespace()
        mock_job.analyzable = SimpleNamespace()
        mock_job.analyzable.name = observable_name
        mock_job.tlp = "clear"
        mock_job.TLP = mock_tlp_enum
        mock_job.user = ""

        return mock_job

    def _setup_analyzer(self, config, observable_type, observable_value):
        logger.info(
            f"Setting up analyzer {self.analyzer_class.__name__} for {observable_type}: {observable_value}"
        )
        analyzer = self.analyzer_class(config)
        analyzer.observable_name = observable_value
        analyzer.observable_classification = observable_type
        analyzer._job = self._create_mock_analyzer_job(observable_value, observable_type)

        for key, value in self.get_extra_config().items():
            setattr(analyzer, key, value)

        return analyzer

    def _validate_response(self, response, observable_type):
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON response for {observable_type}")
                self.fail(
                    f"{self.__class__.__name__}: Analyzer response for {observable_type} is a string but not valid JSON"
                )

        self.assertIsInstance(
            response,
            (dict, list),
            f"{self.__class__.__name__}: Analyzer response for {observable_type} should be a dictionary (JSON object) or list",
        )
        self.assertTrue(
            response,
            f"{self.__class__.__name__}: Analyzer response for {observable_type} should not be empty",
        )
        logger.info(f"Valid response for {observable_type}")

    def test_analyzer_on_supported_observables(self):
        if self.analyzer_class is None:
            self.skipTest(
                f"{self.__class__.__name__}.test_analyzer_on_supported_observables skipped: analyzer_class is not set"
            )

        configs = AnalyzerConfig.objects.filter(python_module=self.analyzer_class.python_module)

        if not configs.exists():
            self.skipTest(
                f"{self.__class__.__name__}: No AnalyzerConfig found for {self.analyzer_class.python_module}"
            )

        config = configs.first()

        for observable_type in config.observable_supported:
            if observable_type == "generic":
                continue

            with self.subTest(observable_type=observable_type):
                logger.info(f"Testing observable type: {observable_type}")

                patches = self.get_mocked_response()
                with self._apply_patches(patches):
                    observable_value = self.get_sample_observable(observable_type)
                    analyzer = self._setup_analyzer(config, observable_type, observable_value)

                    try:
                        response = analyzer.run()
                        self._validate_response(response, observable_type)
                        logger.info(f"Analyzer run successful for {observable_type}")
                    except AnalyzerRunException as e:
                        logger.error(f"AnalyzerRunException for {observable_type}: {e}")
                        self.fail(
                            f"{self.__class__.__name__}: AnalyzerRunException for {observable_type}: {e}"
                        )
                    except Exception as e:
                        logger.exception(f"Unexpected exception for {observable_type}")
                        self.fail(
                            f"{self.__class__.__name__}: Unexpected exception "
                            f"for {observable_type}: {type(e).__name__}: {e}"
                        )
