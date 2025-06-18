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

    @staticmethod
    def get_mocked_response():
        """
        Subclasses should override this method to return a context manager that patches
        any external calls (e.g., requests.get) with their own mocked response.
        """
        raise NotImplementedError("Subclasses must implement get_mocked_response()")

    def test_analyzer_on_supported_observables(self):
        if self.analyzer_class is None:
            self.skipTest("analyzer_class is not set")

        config = AnalyzerConfig.objects.get(
            python_module=self.analyzer_class.python_module
        )

        with self.get_mocked_response():
            for observable_type in config.observable_supported:
                if observable_type == "generic":
                    continue
                with self.subTest(observable_type=observable_type):
                    print(f"Testing observable_type: {observable_type}")
                    observable_value = self.get_sample_observable(observable_type)
                    analyzer = self.analyzer_class(config)
                    analyzer.observable_name = observable_value
                    analyzer.observable_classification = observable_type
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
