# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals

import logging
import typing

from celery import shared_task, signals
from celery.worker.consumer import Consumer
from celery.worker.control import control_command
from django.conf import settings
from django.utils.module_loading import import_string

from api_app import crons
from intel_owl.celery import DEFAULT_QUEUE, app

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
def update(python_module: str):
    from api_app.analyzers_manager.models import AnalyzerConfig
    from intel_owl.celery import broadcast

    analyzer_configs = AnalyzerConfig.objects.filter(python_module=python_module)
    for analyzer_config in analyzer_configs:
        analyzer_config: AnalyzerConfig
        if analyzer_config.is_runnable():
            class_ = analyzer_config.python_class
            if hasattr(class_, "_update") and callable(class_._update):
                if settings.NFS:
                    update_plugin(None, analyzer_config.python_complete_path)
                else:
                    broadcast(
                        update_plugin,
                        queue=analyzer_config.queue,
                        arguments={"plugin_path": analyzer_config.python_complete_path},
                    )
                return True
    else:
        logger.error(f"Unable to update {python_module}")
        return False


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
    job_id: int,
    plugin_path: str,
    plugin_config_pk: str,
    runtime_configuration: dict,
    task_id: int,
    parent_playbook_pk: int = None,
):
    from api_app.core.classes import Plugin

    plugin_class: typing.Type[Plugin] = import_string(plugin_path)
    config = plugin_class.config_model.objects.get(pk=plugin_config_pk)
    plugin = plugin_class(
        config=config,
        job_id=job_id,
        runtime_configuration=runtime_configuration,
        task_id=task_id,
        parent_playbook_pk=parent_playbook_pk,
    )
    plugin.start()


# startup
@signals.worker_ready.connect
def worker_ready_connect(sender: Consumer = None, *args, **kwargs):
    logger.info(f"worker {sender.hostname} ready")
    if sender.hostname == f"celery@worker_{DEFAULT_QUEUE}":
        logger.info("Updating repositories")
        if settings.REPO_DOWNLOADER_ENABLED:
            for python_module in [
                "maxmind.Maxmind",
                "talos.Talos",
                "tor.Tor",
                "yara_scan.YaraScan",
                "quark_engine.QuarkEngine",
            ]:
                update(python_module)
