# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals
import importlib
from celery import shared_task
from guardian import utils

from intel_owl.celery import app
from api_app import crons
from api_app.models import Job
from api_app.analyzers_manager.classes import BaseAnalyzerMixin
from api_app.analyzers_manager.utils import set_report_and_cleanup, set_failed_analyzer
from api_app.connectors_manager.classes import BaseConnectorMixin
from api_app.connectors_manager.utils import set_failed_connector
from api_app.connectors_manager.general import start_connectors

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


@app.task(name="run_analyzer", soft_time_limit=500)
def run_analyzer(cls_path, *args):
    try:
        # FIXME: we can replace this with `django.utils.module_loading`
        # ref to django docs: https://cutt.ly/HzF2rcO
        path_parts = cls_path.split(".")
        typ = path_parts[0]
        modname = ".".join(path_parts[1:-1])
        clsname = path_parts[-1]
        modpath = f"api_app.analyzers_manager.{typ}.{modname}"
        mod = importlib.import_module(modpath)
        if not mod:
            raise Exception(f"Module: {cls_path} couldn't be imported")

        cls: BaseAnalyzerMixin = getattr(mod, clsname)
        if not cls:
            raise Exception(f"Class: {cls_path} couldn't be imported")

        instance: BaseAnalyzerMixin = cls(*args)
        instance.start()
        set_report_and_cleanup(
            instance.analyzer_name,
            instance.job_id,
        )

        # fire connectors when job finishes with success
        job_object = Job.object_by_job_id(instance.job_id)
        if job_object.status == "reported_without_fails":
            app.send_task(
                "on_job_success",
                args=[
                    instance.job_id,
                ],
            )
    except Exception as e:
        set_failed_analyzer(args[0], args[1], str(e))


@app.task(name="on_job_success", soft_time_limit=500)
def on_job_success(_job_id):
    start_connectors(_job_id)


@app.task(name="run_connector", soft_time_limit=500)
def run_connector(cls_path, *args):
    try:
        # FIXME: we can replace this with `django.utils.module_loading`
        # ref to django docs: https://cutt.ly/HzF2rcO
        path_parts = cls_path.split(".")
        typ = path_parts[0]
        modname = ".".join(path_parts[1:-1])
        clsname = path_parts[-1]
        modpath = f"api_app.connectors_manager.{typ}.{modname}"
        mod = importlib.import_module(modpath)
        if not mod:
            raise Exception(f"Module: {cls_path} couldn't be imported")

        cls: BaseConnectorMixin = getattr(mod, clsname)
        if not cls:
            raise Exception(f"Class: {cls_path} couldn't be imported")

        instance: BaseConnectorMixin = cls(*args)
        instance.start()
    except Exception as e:
        set_failed_connector(args[0], args[1], str(e))
        pass
