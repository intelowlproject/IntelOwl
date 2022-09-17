# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from celery import chord
from django.conf import settings

from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.connectors_manager.dataclasses import ConnectorConfig

from ..models import Job
from .dataclasses import PlaybookConfig

logger = logging.getLogger(__name__)


def start_playbooks(
    job_id: int,
) -> None:
    from intel_owl import tasks

    # get job
    job = Job.objects.get(pk=job_id)
    job.update_status(Job.Status.RUNNING)  # set job status to running

    # to store the celery task signatures
    task_signatures = []

    # get playbook config
    playbook_dataclasses = PlaybookConfig.filter(names=job.playbooks_requested)

    final_analyzers_used = []
    final_connectors_used = []

    # loop over and create task signatures
    for p_name, pp in playbook_dataclasses.items():
        # if disabled or unconfigured (this check is bypassed in STAGE_CI)
        if not pp.is_ready_to_use and not settings.STAGE_CI:
            continue

        logger.info(f"STARTED Playbook: ({p_name}, job_id: #{job_id})")

        # Now fetch analyzers and connectors to execute for that playbook
        # and run them below, by fetching their default configurations
        # From their respective config files.
        analyzers = pp.analyzers
        connectors = pp.connectors

        task_signatures_analyzers, analyzers_used = AnalyzerConfig.stack_analyzers(
            job_id=job_id,
            analyzers_to_execute=job.analyzers_to_execute,
            runtime_configuration=analyzers,
            parent_playbook=p_name,
        )

        task_signatures_connectors, connectors_used = ConnectorConfig.stack_connectors(
            job_id=job_id,
            connectors_to_execute=list(connectors.keys()),
            parent_playbook=p_name,
        )

        final_analyzers_used.extend(analyzers_used)
        final_connectors_used.extend(connectors_used)

        task_signatures.extend(task_signatures_analyzers)
        task_signatures.extend(task_signatures_connectors)

    job.update_analyzers_and_connectors_to_execute(
        analyzers_to_execute=final_analyzers_used,
        connectors_to_execute=final_connectors_used,
    )

    runner = chord(task_signatures)
    cb_signature = tasks.post_all_playbooks_finished.signature([job.pk], immutable=True)
    runner(cb_signature)
    return None


def post_all_playbooks_finished(job_id: int) -> None:
    """
    Callback fn that is executed after all playbooks have finished.
    """

    # get job instance
    job = Job.objects.get(pk=job_id)
    # execute some callbacks
    job.job_cleanup()
