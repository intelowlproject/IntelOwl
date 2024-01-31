from logging import getLogger
from typing import Dict, List

from api_app.models import Job
from api_app.pivots_manager.models import PivotReport
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class Pivot(Visualizer):
    def run(self) -> List[Dict]:
        page = self.Page("Job Pivots")

        children_job_list = []
        children_report_list = PivotReport.objects.filter(
            job=self._job,
            config__name__in=self._job.pivots_to_execute.values_list("name", flat=True),
        )
        for child_report in children_report_list:
            content = child_report.report
            if content.get("create_job", False):
                for job in Job.objects.filter(pk__in=content["jobs_id"]):
                    children_job_list.append(self._create_job_ui_element(job))
            else:
                motivation = content.get(
                    "motivation", f"Pivot {child_report.config.name} failed"
                )
                children_job_list.append(
                    self.Base(
                        value=f"Job was not created: {motivation}",
                        disable=False,
                    )
                )

        page.add_level(
            self.Level(
                position=1,
                size=self.LevelSize.S_3,
                horizontal_list=self.HList(
                    value=[
                        self.Title(
                            title=self.Base(
                                value="Job created by",
                                description=(
                                    "This element indicates if the job as been created "
                                    "via pivoting from another job."
                                ),
                            ),
                            value=(
                                self._create_job_ui_element(self._job.parent_job)
                                if self._job.parent_job
                                else self.Base(value="")
                            ),
                            size=self.Size.S_6,
                            disable=not bool(self._job.parent_job),
                        ),
                        self.VList(
                            name=self.Base(
                                value="Created Jobs",
                                description=(
                                    "This is the list of jobs created from "
                                    "the results of this jobs."
                                ),
                                disable=False,
                            ),
                            value=children_job_list,
                            size=self.Size.S_6,
                            start_open=True,
                            disable=not bool(children_job_list),
                        ),
                    ],
                ),
            )
        )

        return [page.to_dict()]

    def _create_job_ui_element(self, job: Job) -> Visualizer.Base:
        return self.Base(
            value=(
                f"Job #{job.pk} ({job.analyzed_object_name}, "
                f"playbook: {job.playbook_to_execute})"
            ),
            link=job.url,
            disable=False,
        )
