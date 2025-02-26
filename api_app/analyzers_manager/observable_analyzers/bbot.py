import logging
import os
from typing import List
from urllib.parse import urlparse

from bbot.scanner import Preset, Scanner
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from intel_owl.settings._util import set_permissions
from tests.mock_utils import if_mock_connections

logger = logging.getLogger(__name__)


class BBOT(ObservableAnalyzer):
    """
    BBOT (Bighuge BLS Open-source Tool) analyzer for domain/URL scanning.
    """

    modules: List[str] = []
    presets: List[str] = ["web-basic"]

    def update(self):
        pass

    def run(self):
        observable = self.observable_name
        logger.info(f"Running BBOT on {observable}")

        # Create the custom output directory (and any missing parent directories)
        files_dir = settings.BBOT_FILES_PATH / f"bbot_analysis_{observable}"
        os.makedirs(files_dir, exist_ok=True)
        set_permissions(files_dir)

        # Monkeypatch BBOT configuration paths so that bbot.yml and secrets.yml get written to files_dir
        from bbot.core.config import files as bbot_files

        bbot_files.BBOTConfigFiles.config_dir = files_dir
        bbot_files.BBOTConfigFiles.config_filename = (files_dir / "bbot.yml").resolve()
        bbot_files.BBOTConfigFiles.secrets_filename = (
            files_dir / "secrets.yml"
        ).resolve()
        os.environ["BBOT_HOME"] = str(files_dir)
        os.environ["HOME"] = str(files_dir)

        # If the observable is a URL, extract the hostname
        if self.observable_classification == Classification.URL:
            logger.debug(f"BBOT extracting hostname from URL {observable}")
            observable = urlparse(observable).hostname

        # Create a Preset object with the output_dir set to files_dir
        preset_obj = Preset(
            observable, output_dir=files_dir, modules=self.modules, presets=self.presets
        )

        # Configure the BBOT scanner with the preset object
        scan = Scanner(
            observable, modules=self.modules, preset=preset_obj, output_modules=["json"]
        )

        # Execute scan and collect results
        results = {"events": [], "stats": None, "errors": []}
        try:
            for event in scan.start():
                event_data = {
                    "type": event.type,
                    "data": event.data,
                    "tags": list(event.tags),
                    "timestamp": (
                        event.timestamp.isoformat() if event.timestamp else None
                    ),
                }
                results["events"].append(event_data)
            results["stats"] = scan.stats
        except Exception as e:
            logger.error(f"BBOT scan failed: {e}", stack_info=True)
            results["errors"].append(str(e))
            raise AnalyzerRunException(e)

        return results

    @classmethod
    def _monkeypatch(cls):
        from unittest.mock import MagicMock, patch

        mock_event = MagicMock()
        mock_event.type = "SCAN"
        mock_event.data = {"target": "example.com", "module": "web-basic"}
        mock_event.tags = ["interesting"]
        mock_event.timestamp = MagicMock()
        mock_event.timestamp.isoformat.return_value = "2024-01-01T00:00:00"

        mock_stats = {"targets_scanned": 1, "modules_executed": 1}

        patches = [
            if_mock_connections(
                patch("bbot.scanner.Scanner.start", return_value=[mock_event]),
                patch("bbot.scanner.Scanner.stats", new_callable=lambda: mock_stats),
            )
        ]
        return super()._monkeypatch(patches=patches)
