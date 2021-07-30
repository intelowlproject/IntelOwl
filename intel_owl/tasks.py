# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals
from celery import shared_task
from guardian import utils

from intel_owl.celery import app
from api_app import crons
from api_app.models import Job
from api_app.analyzers_manager import controller as analyzers_controller
from api_app.connectors_manager import controller as connectors_controller
from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
from api_app.connectors_manager.serializers import ConnectorConfigSerializer

from api_app.analyzers_manager.file_analyzers import yara_scan
from api_app.analyzers_manager.observable_analyzers import (
    maxmind,
    talos,
    tor,
)


@shared_task(soft_time_limit=200)
def clean_orphan_obj_perms():
    utils.clean_orphan_obj_perms()


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


@app.task(name="run_analyzer", soft_time_limit=500)
def run_analyzer(job_id: int, config_dict: dict, **kwargs):
    config = AnalyzerConfigSerializer.dict_to_dataclass(config_dict)
    # run analyzer
    report = analyzers_controller.run_analyzer(job_id, config, **kwargs)
    # get job
    job = report.job
    # execute some callbacks
    # FIXME @eshaan7: find a better place for these callback
    analyzers_controller.job_cleanup(job)
    # fire connectors when job finishes with success
    # avoid re-triggering of connectors (case: recurring analyzer run)
    if job.status == "reported_without_fails" and not len(job.connectors_to_execute):
        app.send_task(
            "on_job_success",
            args=[
                job_id,
            ],
        )


@app.task(name="on_job_success", soft_time_limit=500)
def on_job_success(job_id: int):
    # run all connectors
    connectors_task_id_map = connectors_controller.start_connectors(job_id)
    # update connectors_to_execute field
    job = Job.objects.only("id", "connectors_to_execute").get(pk=job_id)
    job.connectors_to_execute = list(connectors_task_id_map.keys())
    job.save(update_fields=["connectors_to_execute"])


@app.task(name="run_connector", soft_time_limit=500)
def run_connector(job_id: int, config_dict: dict, **kwargs):
    config = ConnectorConfigSerializer.dict_to_dataclass(config_dict)
    connectors_controller.run_connector(job_id, config, **kwargs)
