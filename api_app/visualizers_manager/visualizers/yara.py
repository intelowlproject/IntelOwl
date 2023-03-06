from logging import getLogger
from typing import Dict

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.models import Job, Position
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class Yara(Visualizer):
    def run(self) -> Dict:
        yara_reports = self.analyzer_reports()
        yara_num_matches = sum(
            len(matches)
            for yara_report in yara_reports
            for matches in yara_report.report.values()
        )
        signatures = [
            match["match"]
            for yara_report in yara_reports
            for matches in yara_report.report.values()
            for match in matches
            if match.get("match", None)
        ]
        result = {
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
        logger.debug(result)
        return result

    @classmethod
    def _monkeypatch(cls):
        from kombu import uuid

        AnalyzerReport.objects.create(
            name="Yara",
            job=Job.objects.first(),
            status=AnalyzerReport.Status.SUCCESS,
            report={
                "https://github.com/InQuest/yara-rules": [
                    {
                        "meta": {
                            "URL": "https://github.com/InQuest/yara-rules",
                            "Author": "InQuest Labs",
                            "Description": "Discover embedded PE files, "
                            "without relying on easily stripped/modified "
                            "header strings.",
                        },
                        "path": "/opt/deploy/files_required/"
                        "yara/inquest_yara-rules/PE.rule",
                        "tags": [],
                        "match": "PE_File",
                        "strings": "[(0, '$mz', b'MZ'), "
                        "(280654, '$mz', b'MZ'), "
                        "(288035, '$mz', b'MZ'), "
                        "(291117, '$mz', b'MZ')]",
                    }
                ]
            },
            runtime_configuration={},
            task_id=uuid(),
        )
        patches = []
        return super()._monkeypatch(patches=patches)
