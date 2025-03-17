# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.test import TestCase

from api_app.choices import Classification


class HelperTests(TestCase):
    def test_accept_defanged_domains(self):
        observable = "www\.test\.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = "www[.]test[.]com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

    def test_calculate_observable_classification(self):
        observable = "7.7.7.7"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.IP)

        observable = "www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = ".www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.DOMAIN)

        observable = "ftp://www.test.com"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.URL)

        observable = "b318ff1839771c22e50d316af613dc70"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.HASH)

        observable = "iammeia"
        result = Classification.calculate_observable(observable)
        self.assertEqual(result, Classification.GENERIC)
