# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from unittest import TestCase

from api_app.analyzers_manager.observable_analyzers.phishing.phishing_extractor import (
    PhishingExtractor,
)


class CloakbrowserTestCase(TestCase):
    def test_cloakbrowser_engine(self):
        url = "https://bot.sannysoft.com/"
        analyzer = PhishingExtractor(config={})
        analyzer.observable_name = url
        analyzer.observable_classification = "url"
        analyzer.phishing_engine = "cloakbrowser"
        analyzer.config({})
        result = analyzer.run()
        self.assertIsNotNone(
            result, f"Resullt is Null for {url}"
        )  # Basic test, Added screenshots of comparisons and metrics in https://github.com/intelowlproject/IntelOwl/pull/3940
