from typing import Dict

from api_app.models import Position
from api_app.visualizers_manager.classes import Visualizer


class Yara(Visualizer):
    def run(self) -> Dict:
        yara_report = self._job.analyzer_reports.get(name="Yara")
        yara_num_matches = sum(len(matches) for matches in yara_report.report.values())
        signatures = [
            match["match"]
            for matches in yara_report.report.values()
            for match in matches
            if match.get("match", None)
        ]
        # Tranco
        return {
            "analyzer": {
                "priority": 1,
                "position": Position.CENTER,
                "value": self.__class__.__name__,
            },
            "num_matches": {
                "priority": 1,
                "position": Position.RIGHT,
                "value": yara_num_matches,
            },
            "signatures": {
                "priority": 2,
                "position": Position.LEFT,
                "value": signatures,
            },
        }
