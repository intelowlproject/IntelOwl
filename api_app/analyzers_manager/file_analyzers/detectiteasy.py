import json
import logging

import die

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class DetectItEasy(FileAnalyzer):
    def update(self):
        pass

    def run(self):
        logger.info(f"Running DIE on {self.filepath} for {self.md5}")

        json_report = die.scan_file(
            self.filepath,
            die.ScanFlags.RESULT_AS_JSON,
            str(die.database_path / "db"),
        )
        return json.loads(json_report)
