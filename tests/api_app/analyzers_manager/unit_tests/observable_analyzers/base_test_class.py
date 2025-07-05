import logging
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import TestCase

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig


class BaseAnalyzerTest(TestCase):
    analyzer_class = None
    # Control logging behavior in tests
    suppress_analyzer_logs = True

    def setUp(self):
        """Set up test environment including logging configuration"""
        super().setUp()

        if self.suppress_analyzer_logs and self.analyzer_class:
            # Suppress logs from the specific analyzer being tested
            analyzer_module = self.analyzer_class.__module__
            logging.getLogger(analyzer_module).setLevel(logging.CRITICAL)

            # Also suppress common analyzer manager logs
            logging.getLogger("api_app.analyzers_manager").setLevel(logging.WARNING)

    def tearDown(self):
        """Clean up after test"""
        super().tearDown()

        # Reset logging levels if they were modified
        if self.suppress_analyzer_logs and self.analyzer_class:
            analyzer_module = self.analyzer_class.__module__
            logging.getLogger(analyzer_module).setLevel(logging.NOTSET)
            logging.getLogger("api_app.analyzers_manager").setLevel(logging.NOTSET)

    @classmethod
    def get_sample_observable(cls, observable_type):
        mapping = {
            "domain": "example.com",
            "ip": "8.8.8.8",
            "url": "https://example.com",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "generic": "test@intelowl.com",
        }
        return mapping.get(observable_type, "test")

    @classmethod
    def get_extra_config(cls) -> dict:
        """
        Subclasses can override this to provide additional runtime configuration
        specific to their analyzer (e.g., API keys, URLs, retry counts, etc.).

        Returns:
            dict: Extra configuration parameters for the analyzer
        """
        return {}

    def get_mocked_response(self):
        """
        Subclasses override this to define expected mocked output.

        Can return:
        1. A single patch object: patch('module.function')
        2. A list of patch objects: [patch('module.func1'), patch('module.func2')]
        3. A context manager: patch.multiple() or ExitStack()
        4. None: No mocking needed
        """
        return None

    @classmethod
    def _apply_patches(cls, patches):
        """Helper method to apply single or multiple patches"""
        if patches is None:
            return ExitStack()  # No-op context manager

        # If it's already a context manager, return as-is
        if hasattr(patches, "__enter__") and hasattr(patches, "__exit__"):
            return patches

        # If it's a list of patches, use ExitStack to manage them
        if isinstance(patches, (list, tuple)):
            stack = ExitStack()
            for patch_obj in patches:
                stack.enter_context(patch_obj)
            return stack

        # Single patch object
        return patches

    def _create_mock_analyzer_job(self, observable_name, observable_type):
        """Create a properly structured mock job object"""
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

        return mock_job

    def _setup_analyzer(self, config, observable_type, observable_value):
        """Setup analyzer instance with proper configuration"""
        analyzer = self.analyzer_class(config)
        analyzer.observable_name = observable_value
        analyzer.observable_classification = observable_type
        analyzer._job = self._create_mock_analyzer_job(
            observable_value, observable_type
        )

        # Apply extra configuration
        extra_config = self.get_extra_config()
        for key, value in extra_config.items():
            setattr(analyzer, key, value)

        return analyzer

    def _validate_response(self, response, observable_type):
        """Validate analyzer response format and content"""
        self.assertIsInstance(
            response,
            (dict, list),
            f"Analyzer response for {observable_type} should be a dictionary (JSON object)",
        )
        self.assertTrue(
            response, f"Analyzer response for {observable_type} should not be empty"
        )

        # Additional validation can be added here
        # e.g., check for required fields, data types, etc.

    def test_analyzer_on_supported_observables(self):
        """Test analyzer on all supported observable types"""
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
                print(f"Testing observable_type: {observable_type}")

                # Apply patches using the improved system
                patches = self.get_mocked_response()
                with self._apply_patches(patches):
                    observable_value = self.get_sample_observable(observable_type)
                    analyzer = self._setup_analyzer(
                        config, observable_type, observable_value
                    )

                    try:
                        response = analyzer.run()
                        self._validate_response(response, observable_type)
                        print(f"SUCCESS {observable_type}")

                    except AnalyzerRunException as e:
                        self.fail(
                            f"AnalyzerRunException raised for {observable_type} "
                            f"with valid format: {str(e)}"
                        )
                    except Exception as e:
                        self.fail(
                            f"Unexpected exception for {observable_type}: "
                            f"{type(e).__name__}: {str(e)}"
                        )

    def test_analyzer_error_handling(self):
        """Test analyzer behavior with invalid inputs"""
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

        # Test with invalid observable types if applicable
        invalid_observables = {
            "domain": "invalid..domain",
            "ip": "999.999.999.999",
            "url": "not-a-url",
            "hash": "tooshort",
        }

        for observable_type in config.observable_supported:
            if observable_type in invalid_observables:
                with self.subTest(observable_type=f"{observable_type}_invalid"):
                    patches = self.get_mocked_response()
                    with self._apply_patches(patches):
                        invalid_value = invalid_observables[observable_type]
                        analyzer = self._setup_analyzer(
                            config, observable_type, invalid_value
                        )

                        # Depending on your analyzer's design, this might raise
                        # an exception or return an error response
                        try:
                            response = analyzer.run()
                            # If no exception, validate it's a proper error response
                            self.assertIsInstance(response, (dict, list))
                        except (AnalyzerRunException, ValueError) as e:
                            # Expected behavior for invalid input
                            print(f"Expected error for invalid {observable_type}: {e}")
