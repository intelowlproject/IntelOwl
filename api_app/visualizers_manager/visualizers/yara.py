# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from logging import getLogger
from typing import Dict, List

from api_app.analyzers_manager.models import AnalyzerConfig, AnalyzerReport
from api_app.models import Job
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class Yara(Visualizer):
    def run(self) -> List[Dict]:
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
        levels = self.Level()
        h1 = self.HList(
            value=[
                self.Title(
                    self.Base(
                        value="Analyzer",
                        color=self.Color.DARK,
                    ),
                    self.Base(value=self.__class__.__name__),
                )
            ]
        )
        logger.debug(h1.to_dict())
        levels.add_level(level=1, horizontal_list=h1)
        h2 = self.HList(
            value=[
                self.Title(
                    self.Base(value="N# Matches", color=self.Color.DARK),
                    self.Base(value=yara_num_matches),
                ),
                self.VList(
                    name="Signatures",
                    value=[self.Base(value=value) for value in signatures],
                ),
            ]
        )
        logger.debug(h2.to_dict())
        levels.add_level(level=2, horizontal_list=h2)
        logger.debug(levels)
        return levels.to_dict()

    @classmethod
    def _monkeypatch(cls):
        from kombu import uuid

        report = AnalyzerReport(
            config=AnalyzerConfig.objects.get(name="Yara"),
            job=Job.objects.first(),
            status=AnalyzerReport.Status.SUCCESS,
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
                        "path": "/opt/deploy/files_required/"
                        "yara/inquest_yara-rules/PE.rule",
                        "tags": [],
                        "match": "PE_File",
                        "strings": "[(0, '$mz', b'MZ')]",
                        "rule_url": "https://github.com/InQuest/"
                        "yara-rules/blob/master/PE.rule",
                    }
                ]
            },
            task_id=uuid(),
        )
        report.full_clean()
        report.save()
        patches = []
        return super()._monkeypatch(patches=patches)
