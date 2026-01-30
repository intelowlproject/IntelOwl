# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import Visualizer
from api_app.visualizers_manager.decorators import (
    visualizable_error_handler_with_params,
)

logger = getLogger(__name__)


class Yara(Visualizer):
    @classmethod
    def update(cls) -> bool:
        pass

    @visualizable_error_handler_with_params("Analyzer")
    def _yara_analyzer(self):
        return self.Title(
            self.Base(
                value="Analyzer",
                color=self.Color.DARK,
            ),
            self.Base(value=self.__class__.__name__),
            disable=False,
        )

    @visualizable_error_handler_with_params("N# Matches")
    def _yara_match_number(self, yara_num_matches: int):
        return self.Title(
            self.Base(value="N# Matches", color=self.Color.DARK),
            self.Base(value=yara_num_matches),
            disable=not yara_num_matches,
        )

    @visualizable_error_handler_with_params("VirusTotal")
    def _yara_signatures(self, signatures: List[str]):
        disable_signatures = not signatures
        return self.VList(
            name=self.Base(value="Signatures", disable=disable_signatures),
            value=[self.Base(value=value, disable=disable_signatures) for value in signatures],
            disable=disable_signatures,
        )

    def run(self) -> List[Dict]:
        yara_report = self.get_analyzer_reports().get(config__name="Yara")
        yara_num_matches = sum(len(matches) for matches in yara_report.report.values())
        signatures = [
            match["match"]
            for matches in yara_report.report.values()
            for match in matches
            if match.get("match", None)
        ]
        page1 = self.Page(name="Yara first page")
        h1 = self.HList(value=[self._yara_analyzer()])
        page1.add_level(self.Level(position=1, size=self.LevelSize.S_3, horizontal_list=h1))
        h2 = self.HList(
            value=[
                self._yara_match_number(yara_num_matches),
                self._yara_signatures(signatures),
            ]
        )
        page1.add_level(self.Level(position=2, size=self.LevelSize.S_5, horizontal_list=h2))
        logger.debug(page1)
        return [page1.to_dict()]

    @classmethod
    def _monkeypatch(cls):
        from kombu import uuid

        if not AnalyzerReport.objects.filter(config=AnalyzerConfig.objects.get(name="Yara")).exists():
            report = AnalyzerReport(
                config=AnalyzerConfig.objects.get(name="Yara"),
                job=Job.objects.first(),
                status=AnalyzerReport.STATUSES.SUCCESS,
                report={
                    "inquest_yara-rules": [
                        {
                            "url": "https://github.com/InQuest/yara-rules",
                            "meta": {
                                "URL": "https://github.com/InQuest/yara-rules",
                                "Author": "InQuest Labs",
                                "Description": "Discover embedded PE files,"
                                " without relying on easily stripped/modified "
                                "header strings.",
                            },
                            "path": "/opt/deploy/files_required/yara/inquest_yara-rules/PE.rule",
                            "tags": [],
                            "match": "PE_File",
                            "strings": "[(0, '$mz', b'MZ')]",
                            "rule_url": "https://github.com/InQuest/yara-rules/blob/master/PE.rule",
                        }
                    ]
                },
                task_id=uuid(),
                parameters={},
            )
            report.full_clean()
            report.save()
        patches = []
        return super()._monkeypatch(patches=patches)
