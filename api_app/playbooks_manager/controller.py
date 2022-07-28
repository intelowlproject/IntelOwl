# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, List, Tuple

from celery import chord
from django.conf import settings

from ..analyzers_manager.controller import job_cleanup, stack_analyzers
from ..connectors_manager.controller import stack_connectors

from api_app.exceptions import (
    NotRunnablePlaybook,
)

from ..models import Job
from .dataclasses import PlaybookConfig

logger = logging.getLogger(__name__)


def filter_playbooks(serialized_data: Dict) -> Tuple[List[str]]:
    # init empty list
    valid_playbook_list = []
    selected_playbooks = []
    analyzers_to_be_run = []
    connectors_to_be_run = []
    warnings = []

    # get values from serializer
    playbooks_requested = serialized_data[0].get("playbooks_requested", [])

    # read config
    playbook_dataclasses = PlaybookConfig.all()
    all_playbook_names = list(playbook_dataclasses.keys())

    # run all playbooks; Might just remove this for now.
    run_all = len(playbooks_requested) == 0
    if run_all:
        # select all
        selected_playbooks.extend(all_playbook_names)
    else:
        # select the ones requested
        selected_playbooks.extend(playbooks_requested)

    for p_name in selected_playbooks:
        try:
            pp = playbook_dataclasses.get(p_name, None)
            analyzers_to_be_run.extend(pp.analyzers)
            connectors_to_be_run.extend(pp.connectors)
            if not pp:
                if not run_all:
                    raise NotRunnablePlaybook(
                        f"{p_name} won't run: not present in configuration"
                    )
                continue
            if not pp.is_ready_to_use:
                raise NotRunnablePlaybook(
                    f"{p_name} won't run: not configured"
                )

        except NotRunnablePlaybook as e:
            if run_all:
                # in this case, they are not warnings but expected and wanted behavior
                logger.debug(e)
            else:
                logger.warning(e)
                warnings.append(str(e))
            logger.warning(e)
            warnings.append(str(e))

        else:
            valid_playbook_list.append(p_name)
    analyzers_to_be_run = list(set(analyzers_to_be_run))
    connectors_to_be_run = list(set(connectors_to_be_run))
    return valid_playbook_list, analyzers_to_be_run, connectors_to_be_run, warnings

def start_playbooks(
    job_id: int,
    playbooks_to_execute: List[str],
) -> None:
    from intel_owl import tasks

    # to store the celery task signatures
    task_signatures = []

    # get playbook config
    playbook_dataclasses = PlaybookConfig.filter(names=playbooks_to_execute)

    # get job
    job = Job.objects.get(pk=job_id)
    job.update_status(Job.Status.RUNNING)  # set job status to running

    final_analyzers_used = []
    final_connectors_used = []

    playbooks = list(playbook_dataclasses.items())
    # loop over and create task signatures
    for p_dict in playbooks:
        p_name = p_dict[0]
        pp = p_dict[1]
        # if disabled or unconfigured (this check is bypassed in STAGE_CI)
        if not pp.is_ready_to_use and not settings.STAGE_CI:
            continue

        logger.info(f"STARTED Playbook: ({p_name}, job_id: #{job_id})")

        # Now fetch analyzers and connectors to execute for that playbook
        # and run them below, by fetching their default configurations
        # From their respective config files.
        analyzers = pp.analyzers
        connectors = pp.connectors

        task_signatures_analyzers, analyzers_used = stack_analyzers(
            job_id=job_id,
            analyzers_to_execute=list(analyzers.keys()),
            runtime_configuration=analyzers,
        )

        task_signatures_connectors, connectors_used = stack_connectors(
            job_id=job_id,
            connectors_to_execute=list(connectors.key()),
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
    job_cleanup(job)
