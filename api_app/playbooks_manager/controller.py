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

from api_app.exceptions import NotRunnablePlaybook
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

    # we should not use mutable objects as default to avoid unexpected issues
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
    
    # loop over and create task signatures
    for p_name, pp in playbook_dataclasses.items():
        # if disabled or unconfigured (this check is bypassed in STAGE_CI)
        if not pp.is_ready_to_use and not settings.STAGE_CI:
            continue
        
        # get runtime_configuration if any specified for this playbook
        runtime_params = runtime_configuration.get(p_name, {})
        # gen a new task_id
        task_id = uuid()
        

        
        

   
    