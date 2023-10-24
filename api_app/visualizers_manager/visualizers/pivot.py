from logging import getLogger
from typing import Dict, List

from api_app.models import Job
from api_app.pivots_manager.models import PivotReport
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class Pivot(Visualizer):
    def run(self) -> List[Dict]:
        page = self.Page("Job Pivots")
        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(
                    value=[
                        self.Title(
                            title=self.Base(
                                value="Created by:"
                                if self._job.parent_job
                                else "Job was not created by another job",
                                disable=False,
                            ),
                            value=self.Base(
                                value=f"Job #{self._job.parent_job.pk} with "
                                      f"playbook {self._job.parent_job.playbook_to_execute} "
                                if self._job.parent_job
                                else "",
                                link=Job.objects.get(self._job.parent_job)
                                if self._job.parent_job
                                else "",
                            ),
                            disable=bool(self._job.parent_job),
                        )
                    ],
                ),
            )
        )
        children = []
        reports = PivotReport.objects.filter(
            job=self._job,
            config__name__in=self._job.pivots_to_execute.values_list("name", flat=True),
        )
        if not reports.exists():
            page.add_level(
                self.Level(
                    position=2,
                    size=self.LevelSize.S_3,
                    horizontal_list=self.HList(
                        value=[
                            self.Title(
                                title=self.Base("Job has no pivots", disable=False),
                                value=self.Base("", disable=False),
                                disable=False,
                            )
                        ],
                    ),
                )
            )
        for report in reports:
            children_content = []
            content = report.report
            if content["create_job"]:
                for job in Job.objects.filter(pk__in=content["jobs_id"]):
                    children_content.append(
                        self.Base(
                            value=f"Playbook {job.playbook_to_execute} ->  # {job} ",
                            link=job.url + "/raw",
                            disable=False,
                        )
                    )
            else:
                children_content.append(
                    self.Base(
                        value=f"Job was not created: {content['motivation']}",
                        disable=False,
                    )
                )

            children.append(
                self.VList(
                    name=self.Base(
                        value=f"Pivoting jobs - Pivot {report.config.name} ",
                        disable=False,
                    ),
                    value=[self.HList(value=children_content)],
                    disable=False,
                    open=True,
                )
            )
        page.add_level(
            self.Level(
                position=2,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(value=children),
            )
        )
        return [page.to_dict()]
