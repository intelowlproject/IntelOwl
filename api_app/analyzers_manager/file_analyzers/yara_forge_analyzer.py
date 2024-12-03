import os
import logging
from typing import Dict

from api_app.analyzers_manager.classes import FileAnalyzer, DockerBasedAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)

class YaraForgeAnalyzer(FileAnalyzer, DockerBasedAnalyzer):
    def setup(self):
        # Docker container will handle rules management
        self.rules_dir = "/opt/deploy/yara_rules"

    def run(self) -> Dict:
        try:
            # Call the yara_forge service API endpoint
            response = requests.post(
                f"http://intel_owl_yara_forge:4000/analyze",
                files={"file": open(self.filepath, "rb")}
            )
            response.raise_for_status()
            result = response.json()
            
            return {
                "success": True,
                "matches": result.get("matches", []),
                "summary": {
                    "total_matches": len(result.get("matches", [])),
                    "matched_rules": [match["rule"] for match in result.get("matches", [])]
                }
            }
            
        except Exception as e:
            error_message = f"Error running Yara-forge analyzer: {str(e)}"
            logger.error(error_message)
            raise AnalyzerRunException(error_message)

    @staticmethod
    def _monkeypatch():
        return {
            "success": True,
            "matches": [],
            "summary": {
                "total_matches": 0,
                "matched_rules": []
            }
        }
