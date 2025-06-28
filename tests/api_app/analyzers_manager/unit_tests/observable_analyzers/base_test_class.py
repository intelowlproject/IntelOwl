from contextlib import ExitStack
from types import SimpleNamespace
from unittest import TestCase

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.models import AnalyzerConfig


class BaseAnalyzerTest(TestCase):
    analyzer_class = None

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
        """
        raise NotImplementedError("Subclasses must implement get_mocked_response()")

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

    def test_analyzer_on_supported_observables(self):
        if self.analyzer_class is None:
            self.skipTest("analyzer_class is not set")

        config = AnalyzerConfig.objects.get(
            python_module=self.analyzer_class.python_module
        )

        for observable_type in config.observable_supported:
            if observable_type == "generic":
                continue

            with self.subTest(observable_type=observable_type):
                print(f"Testing observable_type: {observable_type}")

                # Apply patches using the improved system
                patches = self.get_mocked_response()
                with self._apply_patches(patches):
                    observable_value = self.get_sample_observable(observable_type)
                    analyzer = self.analyzer_class(config)
                    analyzer.observable_name = observable_value
                    analyzer.observable_classification = observable_type
                    # Create a mock TLP enum
                    mock_tlp_enum = SimpleNamespace()
                    mock_tlp_enum.CLEAR = SimpleNamespace(value="clear")
                    mock_tlp_enum.GREEN = SimpleNamespace(value="green")
                    mock_tlp_enum.AMBER = SimpleNamespace(value="amber")
                    mock_tlp_enum.RED = SimpleNamespace(value="red")

                    analyzer._job = SimpleNamespace()
                    analyzer._job.analyzable = SimpleNamespace()
                    analyzer._job.analyzable.name = analyzer.observable_name
                    analyzer._job.tlp = "clear"
                    analyzer._job.TLP = mock_tlp_enum

                    extra_config = self.get_extra_config()
                    for key, value in extra_config.items():
                        setattr(analyzer, key, value)

                    try:
                        response = analyzer.run()
                    except AnalyzerRunException:
                        self.fail(
                            f"AnalyzerRunException raised for {observable_type} with valid format"
                        )

                    self.assertIsInstance(
                        response,
                        dict,
                        "Analyzer response should be a dictionary (JSON object)",
                    )
                    self.assertTrue(response, "Analyzer response should not be empty")

                    print(f"SUCCESS {observable_type}")
