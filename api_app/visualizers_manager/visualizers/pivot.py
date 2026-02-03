from logging import getLogger
from typing import Dict, List

from api_app.models import Job
from api_app.pivots_manager.models import PivotConfig
from api_app.visualizers_manager.classes import Visualizer

logger = getLogger(__name__)


class Pivot(Visualizer):
    def run(self) -> List[Dict]:
        page = self.Page("Job Pivots")

        children_element_list = []
        for pivot_report in self._job.pivotreports.all():
            pivot_report_report = pivot_report.report
            children_element = []
            logger.debug(f"{pivot_report_report=}")
            logger.debug(f"{type(pivot_report.config)=}")
            if pivot_report_report.get("create_job", False):
                children_element.extend(
                    [
                        self._create_job_ui_element(
                            job=Job.objects.get(id=pivot_report_report["jobs_id"][0]),
                            pivot_config=pivot_report.config,
                        )
                    ]
                )
            else:
                motivation = pivot_report_report.get("motivation", "")
                if motivation:
                    motivation = f"({motivation})"
                children_element.extend(
                    [
                        self.Base(
                            value="",
                            icon=self.Icon.WARNING,
                            color=self.Color.WARNING,
                            disable=False,
                        ),
                        self.Base(
                            value=(f"{pivot_report.config.name}: Job was not created {motivation}"),
                            description=pivot_report.config.description,
                            disable=False,
                        ),
                    ]
                )

            children_element_list.append(
                self.HList(
                    value=children_element,
                    alignment=self.Alignment.START,
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
                                value="Parent job",
                                description=(
                                    "This element indicates the job that created this "
                                    "job via pivots. In case it's empty it means "
                                    "this job has NOT been created from another."
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
                                value="Children Jobs",
                                description=("This is the list of jobs created from this job via pivots."),
                                disable=False,
                            ),
                            value=children_element_list,
                            size=self.Size.S_6,
                            start_open=True,
                            disable=not bool(children_element_list),
                        ),
                    ],
                ),
            )
        )

        return [page.to_dict()]

    def _create_job_ui_element(self, job: Job, pivot_config: PivotConfig = None) -> Visualizer.Base:
        label = ""
        if pivot_config:
            label += f"{pivot_config.name}: "
        label += f"Job #{job.pk} ({job.analyzable.name}, playbook: {job.playbook_to_execute})"
        return self.Base(
            value=label,
            link=job.url,
            description=pivot_config.description if pivot_config else "",
            disable=False,
        )
