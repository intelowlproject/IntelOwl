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
        logger.info("Setting up test environment")

        if self.suppress_analyzer_logs and self.analyzer_class:
            analyzer_module = self.analyzer_class.__module__
            logging.getLogger(analyzer_module).setLevel(logging.CRITICAL)
            logging.getLogger("api_app.analyzers_manager").setLevel(logging.WARNING)

    def tearDown(self):
        super().tearDown()
        logger.info("Tearing down test environment")

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
        return {}

    def get_mocked_response(self):
        return None

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
        logger.info(f"Setting up analyzer for {observable_type}: {observable_value}")
        analyzer = self.analyzer_class(config)
        analyzer.observable_name = observable_value
        analyzer.observable_classification = observable_type
        analyzer._job = self._create_mock_analyzer_job(
            observable_value, observable_type
        )

        for key, value in self.get_extra_config().items():
            setattr(analyzer, key, value)

        return analyzer

    def _validate_response(self, response, observable_type):
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                logger.error("Invalid JSON response for %s", observable_type)
                self.fail(
                    f"Analyzer response for {observable_type} is a string but not valid JSON"
                )

        self.assertIsInstance(
            response,
            (dict, list),
            f"Analyzer response for {observable_type} should be a dictionary (JSON object)",
        )
        self.assertTrue(
            response, f"Analyzer response for {observable_type} should not be empty"
        )
        logger.info("Valid response for %s", observable_type)

    def test_analyzer_on_supported_observables(self):
        if self.analyzer_class is None:
            self.skipTest("analyzer_class is not set")

        configs = AnalyzerConfig.objects.filter(
            python_module=self.analyzer_class.python_module
        )

        if not configs.exists():
            self.skipTest(
                f"No AnalyzerConfig found for {self.analyzer_class.python_module}"
            )

        config = configs.first()

        for observable_type in config.observable_supported:
            if observable_type == "generic":
                continue

            with self.subTest(observable_type=observable_type):
                logger.info("Testing observable type: %s", observable_type)

                patches = self.get_mocked_response()
                with self._apply_patches(patches):
                    observable_value = self.get_sample_observable(observable_type)
                    analyzer = self._setup_analyzer(
                        config, observable_type, observable_value
                    )

                    try:
                        response = analyzer.run()
                        self._validate_response(response, observable_type)
                        logger.info("Analyzer run successful for %s", observable_type)
                    except AnalyzerRunException as e:
                        logger.error("AnalyzerRunException: %s", e)
                        self.fail(
                            f"AnalyzerRunException for {observable_type}: {str(e)}"
                        )
                    except Exception as e:
                        logger.exception("Unexpected exception for %s", observable_type)
                        self.fail(
                            f"Unexpected exception for {observable_type}: {type(e).__name__}: {str(e)}"
                        )
