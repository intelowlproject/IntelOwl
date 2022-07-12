# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, List

from celery import group, uuid
from django.conf import settings
from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.connectors_manager.dataclasses import ConnectorConfig

from api_app.exceptions import NotRunnableAnalyzer, NotRunnableConnector, NotRunnablePlaybook
from ..models import TLP, Job
from intel_owl.consts import DEFAULT_QUEUE

from .dataclasses import PlaybookConfig

logger = logging.getLogger(__name__)


def filter_playbooks(serialized_data: Dict, warnings: List[str]) -> List[str]:
    # init empty list
    cleaned_playbook_list = []
    selected_playbooks = []
    analyzers_to_be_run = []
    connectors_to_be_run = []

    # get values from serializer
    playbooks_requested = serialized_data.get("playbooks_requested", [])
    
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
                        f"{p_name} won't run: not available for configuration"
                    )
                continue
            if not pp.is_ready_to_use:  # check configured/disabled
                raise NotRunnablePlaybook(
                    f"{p_name} won't run: is disabled or unconfigured"
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
            cleaned_playbook_list.append(p_name)
    analyzers_to_be_run = list(set(analyzers_to_be_run))
    connectors_to_be_run = list(set(connectors_to_be_run))
    return cleaned_playbook_list, analyzers_to_be_run, connectors_to_be_run


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

    analyzers_used = []
    connectors_used = []
    
    playbooks = list(playbook_dataclasses.items())
    # loop over and create task signatures
    for p_dict in playbooks:
        p_name = p_dict[0]
        pp = p_dict[1]
        # if disabled or unconfigured (this check is bypassed in STAGE_CI)
        if not pp.is_ready_to_use and not settings.STAGE_CI:
            continue

        # Now fetch analyzers and connectors to execute for that playbook
        # and run them below, by fetching their default configurations
        # From their respective config files.
        analyzers = pp.analyzers
        connectors = pp.connectors

        for a_name in analyzers:
            if a_name in analyzers_used:
                continue
            aa = AnalyzerConfig.get(a_name)
            a_params = analyzers.get(a_name)

            try:
                if aa is None:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't run: not available in configuration"
                    )
                    continue
            
                if not aa.is_ready_to_use:
                    raise NotRunnableAnalyzer(
                        f"{a_name} won't run: is disabled or unconfigured"
                    )
                    continue
                analyzers_used.append(a_name)
                task_id = uuid()
                args = [
                        job_id,
                        aa.asdict(),
                        {"runtime_configuration": a_params, "task_id": task_id},
                        p_name
                    ]

                # get celery queue
                queue = aa.config.queue
                if queue not in settings.CELERY_QUEUES:
                    logger.error(
                        f"Analyzer {a_name} has a wrong queue."
                        f"Setting to `{DEFAULT_QUEUE}`"
                    )
                    queue = DEFAULT_QUEUE
                # get soft_time_limit
                soft_time_limit = aa.config.soft_time_limit
                task_signatures.append(
                    tasks.run_analyzer.signature(
                        args,
                        {},
                        queue=queue,
                        soft_time_limit=soft_time_limit,
                        task_id=task_id,
                        ignore_result=True, # since we are using group and not chord
                    )
                )

            except NotRunnableAnalyzer as e:
                logger.warning(e)
        
        for c_name in connectors:
            if c_name in connectors_used:
                continue
            cc = ConnectorConfig.get(c_name)
            c_params = connectors.get(c_name)

            try:
                if cc is None:
                    raise NotRunnableConnector(
                        f"{c_name} won't run: not available in configuration"
                    )
                    
                # if disabled or unconfigured (this check is bypassed in STAGE_CI)
                if not cc.is_ready_to_use and not settings.STAGE_CI:
                    raise NotRunnableConnector(
                        f"{c_name} won't run: is disabled or unconfigured"
                    )
                    
                connectors_used.append(c_name)
                task_id = uuid()
                args = [
                    job_id,
                    cc.asdict(),
                    {"runtime_configuration": c_params, "task_id": task_id, "parent_playbook": p_name},
                ]

                # get celery queue
                queue = cc.config.queue
                if queue not in settings.CELERY_QUEUES:
                    logger.error(
                        f"Connector {c_name} has a wrong queue."
                        f" Setting to `{DEFAULT_QUEUE}`"
                    )
                queue = DEFAULT_QUEUE
                # get soft_time_limit
                soft_time_limit = cc.config.soft_time_limit
                # create task signature and add to list
                task_signatures.append(
                tasks.run_connector.signature(
                        args,
                        {},
                        queue=queue,
                        soft_time_limit=soft_time_limit,
                        task_id=task_id,
                        ignore_result=True,  # since we are using group and not chord
                    )
                )

            except NotRunnableConnector as e:
                logger.warning(e)
    mygroup = group(task_signatures)
    mygroup()

    return None