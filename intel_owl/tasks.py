# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals

import logging
import typing

from celery import shared_task, signals
from celery.worker.control import control_command
from django.conf import settings
from django.utils.module_loading import import_string

from api_app import crons
from intel_owl.celery import app

logger = logging.getLogger(__name__)


@control_command(
    args=[("plugin_path", str)],
)
def update_plugin(state, plugin_path):
    plugin = import_string(plugin_path)
    plugin._update()


@shared_task(soft_time_limit=10000)
def remove_old_jobs():
    crons.remove_old_jobs()


@shared_task(soft_time_limit=120)
def check_stuck_analysis():
    crons.check_stuck_analysis()


@shared_task(soft_time_limit=60)
def talos_updater():
    from api_app.analyzers_manager.models import AnalyzerConfig

    AnalyzerConfig.update("talos.Talos")


@shared_task(soft_time_limit=60)
def tor_updater():
    from api_app.analyzers_manager.models import AnalyzerConfig

    AnalyzerConfig.update("tor.Tor")


@shared_task(soft_time_limit=60)
def quark_updater():
    from api_app.analyzers_manager.models import AnalyzerConfig

    AnalyzerConfig.update("quark_engine.QuarkEngine")


@shared_task(soft_time_limit=20)
def maxmind_updater():
    from api_app.analyzers_manager.models import AnalyzerConfig

    AnalyzerConfig.update("maxmind.Maxmind")


@shared_task(soft_time_limit=60)
def yara_updater():
    from api_app.analyzers_manager.models import AnalyzerConfig

    AnalyzerConfig.update("yara_scan.YaraScan")


@shared_task(soft_time_limit=100)
def update_notifications_with_releases():
    from django.core import management

    management.call_command(
        "changelog_notification",
        ".github/CHANGELOG.md",
        "INTELOWL",
        "--number-of-releases",
        "1",
    )


@app.task(name="continue_job_pipeline", soft_time_limit=20)
def continue_job_pipeline(job_id: int):

    from api_app.models import Job

    job = Job.objects.get(pk=job_id)
    # execute some callbacks
    job.job_cleanup()


@app.task(name="job_pipeline", soft_time_limit=100)
def job_pipeline(
    job_id: int,
    runtime_configuration: typing.Dict[str, typing.Any],
):
    from api_app.models import Job

    job = Job.objects.get(pk=job_id)
    job.pipeline(runtime_configuration)


@app.task(name="run_plugin", soft_time_limit=500)
def run_plugin(
    job_id: int, plugin_path: str, plugin_config_pk: str, report_defaults: dict
):
    from api_app.core.classes import Plugin

    plugin: Plugin = import_string(plugin_path)
    config_class = plugin.config_model
    instance = config_class.objects.get(pk=plugin_config_pk)
    instance.run(job_id, report_defaults)


# startup
@signals.worker_ready.connect
def worker_ready_connect(*args, **kwargs):
    from api_app.analyzers_manager.models import AnalyzerConfig

    logger.info("workers ready")
    if settings.REPO_DOWNLOADER_ENABLED:
        AnalyzerConfig.update("yara_scan.YaraScan")
