# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.test import SimpleTestCase

from api_app.data_model_manager.classify import classify
from api_app.data_model_manager.enums import DataModelEvaluations


class ClassifyTestCase(SimpleTestCase):
    def test_trusted_high_reliability_is_trusted(self):
        self.assertEqual(classify(DataModelEvaluations.TRUSTED.value, 8), "trusted")
        self.assertEqual(classify(DataModelEvaluations.TRUSTED.value, 10), "trusted")

    def test_trusted_below_eight_is_clean(self):
        self.assertEqual(classify(DataModelEvaluations.TRUSTED.value, 7), "clean")
        self.assertEqual(classify(DataModelEvaluations.TRUSTED.value, 0), "clean")

    def test_malicious_high_reliability_is_malicious(self):
        self.assertEqual(classify(DataModelEvaluations.MALICIOUS.value, 6), "malicious")
        self.assertEqual(classify(DataModelEvaluations.MALICIOUS.value, 10), "malicious")

    def test_malicious_below_six_is_suspicious(self):
        self.assertEqual(classify(DataModelEvaluations.MALICIOUS.value, 5), "suspicious")
        self.assertEqual(classify(DataModelEvaluations.MALICIOUS.value, 0), "suspicious")

    def test_none_or_unknown_is_no_evaluation(self):
        self.assertEqual(classify(None, 9), "no evaluation")
        self.assertEqual(classify("", 9), "no evaluation")
        self.assertEqual(classify("whatever", 9), "no evaluation")
