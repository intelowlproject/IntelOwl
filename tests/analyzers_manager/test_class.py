from django.test import TestCase

from api_app.analyzers_manager.observable_analyzers import greynoiseintel, talos
from api_app.analyzers_manager.observable_analyzers.vt import vt2_get


class BaseAnalyzerTests(TestCase):
    def test_enabled(self):
        # Just testing that the flag "enabled" works based...
        # on the default configuration of some analyzers
        # All related analyzers (1) is enabled
        self.assertTrue(talos.Talos.enabled)
        # one related analyzer is not enabled
        self.assertTrue(greynoiseintel.GreyNoiseAnalyzer.enabled)
        # should all be disabled
        self.assertFalse(vt2_get.VirusTotalv2.enabled)
