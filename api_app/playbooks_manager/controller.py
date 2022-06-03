# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Dict, List

from celery import group, uuid
from django.conf import settings
from django.utils.module_loading import import_string
from rest_framework.exceptions import ValidationError
from api_app.analyzers_manager.dataclasses import AnalyzerConfig
from api_app.connectors_manager.dataclasses import ConnectorConfig

from api_app.exceptions import NotRunnableAnalyzer, NotRunnableConnector, NotRunnablePlaybook
from api_app.models import TLP
from intel_owl.consts import DEFAULT_QUEUE

from .classes import Playbook
from .dataclasses import PlaybookConfig
from .models import PlaybookReport

logger = logging.getLogger(__name__)


def filter_playbooks(serialized_data: Dict, warnings: List[str]) -> List[str]:
    # init empty list
    cleaned_playbook_list = []
    selected_playbooks = []

    # get values from serializer
    playbooks_requested = serialized_data.get("playbooks_requested", [])
    tlp = serialized_data.get("tlp", TLP.WHITE).upper()

    # read config
    playbook_dataclasses = PlaybookConfig.all()
    all_playbook_names = list(playbook_dataclasses.keys())

    # run all connectors ?
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

        else:
            cleaned_playbook_list.append(p_name)
    
    return cleaned_playbook_list


def start_playbooks(
    job_id: int,
    playbooks_to_execute: List[str],
    runtime_configuration: Dict[str, Dict] = None
) -> None:
    from intel_owl import tasks

    analyzers_to_run = {}
    connectors_to_run = {}
    # we should not use mutable objects as default to avoid unexpected issues
    print(runtime_configuration)
    print(playbooks_to_execute)
    if runtime_configuration is None:
        runtime_configuration = {}
    
    # to store the celery task signatures
    task_signatures = []

    # get playbook config
    playbook_dataclasses = PlaybookConfig.filter(names=playbooks_to_execute)

    analyzer_dataclasses = AnalyzerConfig.all()
    connector_dataclasses = ConnectorConfig.all()

    all_analyzer_names = list(analyzer_dataclasses.keys())
    all_connector_names = list(connector_dataclasses.keys())
    
    playbooks = playbook_dataclasses.items()
    # loop over and create task signatures
    for p_name in playbooks:
        pp = playbooks.get(p_name)
        # if disabled or unconfigured (this check is bypassed in STAGE_CI)
        if not pp.is_ready_to_use and not settings.STAGE_CI:
            continue
        
        # get runtime_configuration if any specified for this playbook
        runtime_params = runtime_configuration.get(p_name, {})
        # gen a new task_id
        # Now fetch analyzers and connectors to execute for that playbook
        # and run them below, by fetching their default configurations
        # From their respective config files.
        analyzers = pp.analyzers
        connectors = pp.connectors

        for a_name in analyzers:
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
                args = [
                        job_id,
                        aa.asdict(),
                        {"runtime_configuration": a_params, "task_id": task_id},
                    ]
                task_id = uuid()
                analyzers_to_run[a_name] = dict(
                    args=args
                )
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
            cc = ConnectorConfig.get(c_name)
            c_params = connectors.get(c_name)
            
            try:
                if cc is None:
                    raise NotRunnableConnector(
                        f"{c_name} won't run: not available in configuration"
                    )
                    continue
                # if disabled or unconfigured (this check is bypassed in STAGE_CI)
                if not cc.is_ready_to_use and not settings.STAGE_CI:
                    raise NotRunnableAnalyzer(
                        f"{c_name} won't run: is disabled or unconfigured"
                    )
                    continue
                        # get celery queue
                task_id = uuid()
                args = [
                    job_id,
                    cc.asdict(),
                    {"runtime_configuration": c_params, "task_id": task_id},
                ]
                connectors_to_run[c_name] = dict(
                    args=args
                )
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


def set_failed_playbook(
    job_id: str,
    name: str,
    err_msg: str, 
    **report_defaults
) -> PlaybookReport:
    status = PlaybookReport.status.FAILED
    logger.warning(f"({name}, job_id #{job_id}) -> set as {status}. Error: {err_msg}")
    report, _ = PlaybookReport.objects.get_or_create(
        job_id=job_id, name=name, defaults=report_defaults
    )
    report.status = status
    report.errors.append(err_msg)
    report.save()
    return report