# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import subprocess
from unittest import skipIf

from api_app.analyzers_manager.file_analyzers.capa_info import CapaInfo
from api_app.models import Job
from tests import CustomTestCase


def _capa_available() -> bool:
    """Return True if capa binary is runnable (for skipIf)."""
    try:
        subprocess.run(
            ["/usr/local/bin/capa", "--version"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


class CapaInfoTestCase(CustomTestCase):
    fixtures = [
        "api_app/fixtures/0001_user.json",
    ]

    @staticmethod
    def tearDown() -> None:
        Job.objects.all().delete()

    @skipIf(
        not _capa_available(),
        "capa binary not available",
    )
    def test_capa_on_malware_sample(self):
        """Run Capa_Info on the real malware sample for reproducibility."""
        report = self._analyze_sample(
            "capa_malware_sample.exe",
            "3c1408052d854449ec6dade9dc5b3596",
            "application/x-dosexec",
            "Capa_Info",
            CapaInfo,
        )
        self.assertIn("rules", report)
        self.assertIn("meta", report)
        self.assertIsInstance(report["rules"], dict)
