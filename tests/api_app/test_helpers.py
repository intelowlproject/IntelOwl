from django.test import TestCase

from api_app.analyzers_manager.constants import ObservableTypes
from api_app.helpers import calculate_observable_classification


class HelperTests(TestCase):
    def test_accept_defanged_domains(self):
        observable = "www\.test\.com"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.DOMAIN)

        observable = "www[.]test[.]com"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.DOMAIN)

    def test_calculate_observable_classification(self):
        observable = "7.7.7.7"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.IP)

        observable = "www.test.com"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.DOMAIN)

        observable = ".www.test.com"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.DOMAIN)

        observable = "ftp://www.test.com"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.URL)

        observable = "b318ff1839771c22e50d316af613dc70"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.HASH)

        observable = "iammeia"
        result = calculate_observable_classification(observable)
        self.assertEqual(result, ObservableTypes.GENERIC)
