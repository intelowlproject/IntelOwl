# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from celery import chord, group
from django.conf import settings

from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.connectors_manager.dataclasses import ConnectorConfig

from ..models import Job
from .dataclasses import PlaybookConfig

logger = logging.getLogger(__name__)


def start_playbooks(
    job_id: int,
    runtime_configuration: dict,
) -> None:
    from intel_owl import tasks

    # get job
    job = Job.objects.get(pk=job_id)
    job_owner = job.user
    job.update_status(Job.Status.RUNNING)  # set job status to running

    # to store the celery task signatures
    final_task_signatures_analyzers = []
    final_task_signatures_connectors = []

    # get playbook config
    playbook_dataclasses = PlaybookConfig.filter(
        names=job.playbooks_to_execute,
        user=job_owner
    )

    final_analyzers_used = []
    final_connectors_used = []

    # loop over and create task signatures
    for p_name, pp in playbook_dataclasses.items():
        # if disabled or unconfigured (this check is bypassed in STAGE_CI)
        if not pp.is_ready_to_use and not settings.STAGE_CI:
            continue

        logger.info(f"STARTED Playbook: ({p_name}, job_id: #{job_id})")

        playbook_analyzers = list(pp.analyzers.keys())
        playbook_connectors = list(pp.connectors.keys())

        # Now fetch analyzers and connectors to execute for that playbook
        # and run them below, by fetching their default configurations
        # From their respective config files.
        analyzer_configuration = (
            runtime_configuration if runtime_configuration else pp.analyzers
        )
        connector_configuration = (
            runtime_configuration if runtime_configuration else pp.connectors
        )

        analyzers_to_execute = []
        connectors_to_execute = []

        for analyzer in playbook_analyzers:
            if (
                analyzer in job.analyzers_to_execute
                and analyzer not in final_analyzers_used
            ):
                analyzers_to_execute.append(analyzer)

        for connector in playbook_connectors:
            if (
                connector in job.connectors_to_execute
                and connector not in final_connectors_used
            ):
                connectors_to_execute.append(connector)

        task_signatures_analyzers, analyzers_used = AnalyzerConfig.stack_analyzers(
            job_id=job_id,
            analyzers_to_execute=analyzers_to_execute,
            runtime_configuration=analyzer_configuration,
            parent_playbook=p_name,
        )

        task_signatures_connectors, connectors_used = ConnectorConfig.stack_connectors(
            job_id=job_id,
            connectors_to_execute=connectors_to_execute,
            parent_playbook=p_name,
            runtime_configuration=connector_configuration,
        )

        final_analyzers_used.extend(analyzers_used)
        final_connectors_used.extend(connectors_used)

        final_task_signatures_analyzers.extend(task_signatures_analyzers)
        final_task_signatures_connectors.extend(task_signatures_connectors)

    # first, fire all the analyzers
    runner = chord(final_task_signatures_analyzers)

    # then once the analyzers are done running, fire all
    # the connectors
    cb_signature = tasks.post_all_playbooks_finished.signature(
        [job.pk, final_task_signatures_connectors], immutable=True
    )
    runner(cb_signature)
    return


def post_all_playbooks_finished(
    job_id: int,
    connectors_task_signatures: list,
) -> None:
    """
    Callback fn that is executed after all playbooks have finished.
    """
    # get job instance
    job = Job.objects.get(pk=job_id)
    # execute some callbacks
    job.job_cleanup()
    # fire connectors when job finishes with success
    # avoid re-triggering of connectors (case: recurring analyzer run)
    if job.status == Job.Status.REPORTED_WITHOUT_FAILS and (
        len(job.connectors_to_execute) > 0 and job.connector_reports.count() == 0
    ):
        # fire the connectors in a grouped celery task
        # https://docs.celeryproject.org/en/stable/userguide/canvas.html
        mygroup = group(connectors_task_signatures)
        mygroup()

    return None
