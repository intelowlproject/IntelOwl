# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals

from celery import shared_task

from api_app import crons
from api_app.analyzers_manager import controller as analyzers_controller
from api_app.analyzers_manager.file_analyzers import yara_scan
from api_app.analyzers_manager.observable_analyzers import maxmind, talos, tor
from api_app.connectors_manager import controller as connectors_controller
from api_app.playbooks_manager import controller as playbooks_controller
from intel_owl.celery import app


@shared_task(soft_time_limit=10000)
def remove_old_jobs():
    crons.remove_old_jobs()


@shared_task(soft_time_limit=120)
def check_stuck_analysis():
    crons.check_stuck_analysis()


@shared_task(soft_time_limit=60)
def talos_updater():
    talos.Talos.updater()


@shared_task(soft_time_limit=60)
def tor_updater():
    tor.Tor.updater()


@shared_task(soft_time_limit=20)
def maxmind_updater():
    for db in maxmind.db_names:
        maxmind.Maxmind.updater({}, db)


@shared_task(soft_time_limit=60)
def yara_updater():
    yara_scan.YaraScan.yara_update_repos()


@app.task(name="start_analyzers", soft_time_limit=100)
def start_analyzers(
    job_id: int,
    analyzers_to_execute: list,
    runtime_configuration: dict,
):
    analyzers_controller.start_analyzers(
        job_id, analyzers_to_execute, runtime_configuration
    )


@app.task(name="post_all_analyzers_finished", soft_time_limit=100)
def post_all_analyzers_finished(job_id: int, runtime_configuration: dict):
    analyzers_controller.post_all_analyzers_finished(job_id, runtime_configuration)


@app.task(name="post_all_playbooks_finished", soft_time_limit=60)
def post_all_playbooks_finished(job_id: int, connectors_task_signatures: list):
    playbooks_controller.post_all_playbooks_finished(job_id, connectors_task_signatures)


@app.task(name="run_analyzer", soft_time_limit=500)
def run_analyzer(
    job_id: int, config_dict: dict, report_defaults: dict, parent_playbook: str = ""
):
    analyzers_controller.run_analyzer(
        job_id, config_dict, report_defaults, parent_playbook
    )


@app.task(name="run_connector", soft_time_limit=500)
def run_connector(
    job_id: int, config_dict: dict, report_defaults: dict, parent_playbook: str = ""
):
    connectors_controller.run_connector(
        job_id, config_dict, report_defaults, parent_playbook
    )


@app.task(name="start_connectors", soft_time_limit=100)
def start_connectors(
    job_id: int,
    connectors_to_execute: list,
    runtime_configuration: dict,
):
    connectors_controller.start_connectors(
        job_id, connectors_to_execute, runtime_configuration
    )


@app.task(name="start_playbooks", soft_time_limit=500)
def start_playbooks(
    job_id: int,
    runtime_configuration: dict,
):
    playbooks_controller.start_playbooks(job_id, runtime_configuration)
