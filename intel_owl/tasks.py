# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals

import logging
import typing

from celery import shared_task, signals

from api_app import crons
from api_app.analyzers_manager.file_analyzers import quark_engine, yara_scan
from api_app.analyzers_manager.observable_analyzers import maxmind, talos, tor
from certego_saas.models import User
from intel_owl.celery import app

logger = logging.getLogger(__name__)


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


@shared_task(soft_time_limit=60)
def quark_updater():
    quark_engine.QuarkEngine.updater()


@shared_task(soft_time_limit=20)
def maxmind_updater():
    for db in maxmind.db_names:
        maxmind.Maxmind.updater({}, db)


@shared_task(soft_time_limit=60)
def yara_updater():
    yara_scan.YaraScan.yara_update_repos()


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


@app.task(name="run_analyzer", soft_time_limit=500)
def run_analyzer(job_id: int, config_dict: dict, report_defaults: dict):
    from api_app.analyzers_manager.dataclasses import AnalyzerConfig

    config = AnalyzerConfig.from_dict(config_dict)
    config.run(job_id, report_defaults)


@app.task(name="run_connector", soft_time_limit=500)
def run_connector(job_id: int, config_dict: dict, report_defaults: dict):
    from api_app.connectors_manager.dataclasses import ConnectorConfig

    config = ConnectorConfig.from_dict(config_dict)
    config.run(job_id, report_defaults)


@shared_task()
def build_config_cache(plugin_type: str, user_pk: int = None):
    from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
    from api_app.connectors_manager.serializers import ConnectorConfigSerializer
    from api_app.models import PluginConfig

    # we "greedy cache" the config at start of application
    # because it is an expensive operation
    # we can't have the class as parameter because we run celery not in pickle mode
    if plugin_type == PluginConfig.PluginType.ANALYZER:
        serializer_class = AnalyzerConfigSerializer
    elif plugin_type == PluginConfig.PluginType.CONNECTOR:
        serializer_class = ConnectorConfigSerializer
    else:
        raise TypeError(f"Unable to parse plugin type {plugin_type}")
    user = User.objects.get(pk=user_pk) if user_pk else None

    serializer_class.read_and_verify_config.invalidate(serializer_class, user)
    serializer_class.read_and_verify_config(user)


@signals.worker_ready.connect
def worker_ready_connect(*args, **kwargs):

    from api_app.models import PluginConfig

    logger.info("worker ready, generating cache")

    build_config_cache(PluginConfig.PluginType.ANALYZER.value)
    build_config_cache(PluginConfig.PluginType.CONNECTOR.value)
    for user in User.objects.all():
        build_config_cache(PluginConfig.PluginType.ANALYZER.value, user_pk=user.pk)
        build_config_cache(PluginConfig.PluginType.CONNECTOR.value, user_pk=user.pk)
