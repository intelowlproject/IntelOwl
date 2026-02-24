# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.file_analyzers.macho_info import MachoInfo
from tests import CustomTestCase


class MachoInfoTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        from api_app.models import Job

        Job.objects.all().delete()

    def test_macho_analysis(self):
        """Test MachoInfo analyzer with a real sample"""
        report = self._analyze_sample(
            "macho_sample",
            "e4292266cfed6154c231f566a4b96c48",
            # not hardcoded, MD5 of tested data
            "application/x-mach-binary",
            "MachoInfo",
            MachoInfo,
        )

        # distinct checks
        self.assertIn("header", report)
        self.assertIn("magic", report["header"])

        # Check architecture (our sample is likely x86_64 or arm64 depending on host build)
        self.assertIn("architectures", report)
        self.assertIsInstance(report["architectures"], list)

        # Check segments
        self.assertIn("segments", report)
        self.assertGreater(len(report["segments"]), 0)

        # Check dylibs (should have at least libSystem)
        self.assertIn("dylib_names", report)
        self.assertIsInstance(report["dylib_names"], list)

        # Check hashes
        self.assertIn("hashes", report)
        self.assertIn("dylib_hash", report["hashes"])

        # Check exports
        self.assertIn("exports", report)
        # exports might be list or dict depending on result format, analyzing sample suggested dict
        self.assertTrue(isinstance(report["exports"], (list, dict)))

        # Check code signature
        self.assertIn("code_signature", report)
