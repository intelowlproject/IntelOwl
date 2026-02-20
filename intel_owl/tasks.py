# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from __future__ import absolute_import, unicode_literals

import datetime
import json
import logging
import typing
import uuid
from typing import Dict, List

import inflection
from celery import Task, shared_task, signals
from celery.worker.consumer import Consumer
from celery.worker.control import control_command
from celery.worker.request import Request
from django.conf import settings
from django.utils.timezone import now
from django_celery_beat.models import PeriodicTask
from elasticsearch.helpers import bulk

from api_app.choices import ReportStatus, Status
from intel_owl import secrets
from intel_owl.celery import app, get_queue_name
from intel_owl.settings._util import get_environment

logger = logging.getLogger(__name__)


class FailureLoggedRequest(Request):
    def on_timeout(self, soft, timeout):
        result = super().on_timeout(soft, timeout)
        if not soft:
            logger.warning(f"A hard timeout was enforced for task {self.task.name}")
        return result

    def on_failure(self, exc_info, send_failed_event=True, return_ok=False):
        logger.critical(
            f"Failure detected for task {self.task.name}"
            f" with exception {exc_info} and request {self._request_dict}"
        )
        return super().on_failure(exc_info, send_failed_event=send_failed_event, return_ok=return_ok)


class FailureLoggedTask(Task):
    Request = FailureLoggedRequest


@control_command(
    args=[("python_module_pk", int)],
)
def update_plugin(state, python_module_pk: int):
    from api_app.models import PythonModule

    pm: PythonModule = PythonModule.objects.get(pk=python_module_pk)
    pm.python_class.update()


@shared_task(base=FailureLoggedTask, soft_time_limit=300)
def execute_ingestor(config_name: str):
    from api_app.ingestors_manager.classes import Ingestor
    from api_app.ingestors_manager.models import IngestorConfig

    config: IngestorConfig = IngestorConfig.objects.get(name=config_name)
    if config.disabled:
        logger.info(f"Not executing ingestor {config.name} because disabled")
    else:
        class_: typing.Type[Ingestor] = config.python_module.python_class
        obj: Ingestor = class_(config=config)
        obj.start({}, None, None)  # runtime_configuration, job_id, task_id
        logger.info(f"Executing ingestor {config.name}")


@shared_task(base=FailureLoggedTask, soft_time_limit=10000)
def remove_old_jobs():
    """
    this is to remove old jobs to avoid to fill the database.
    Retention can be modified.
    """
    from api_app.models import Job

    logger.info("started remove_old_jobs")

    retention_days = int(secrets.get_secret("OLD_JOBS_RETENTION_DAYS", 14))
    date_to_check = now() - datetime.timedelta(days=retention_days)
    old_jobs = Job.objects.filter(finished_analysis_time__lt=date_to_check)
    num_jobs_to_delete = old_jobs.count()
    logger.info(f"found {num_jobs_to_delete} old jobs to delete")
    for old_job in old_jobs.iterator():
        # if the job that we are going to delete is the last one, and it has a file
        if old_job.analyzable.jobs.count() == 1 and old_job.analyzable.file:
            old_job.analyzable.file.delete()
        try:
            old_job.delete()
        except Job.DoesNotExist as e:
            logger.warning(f"job {old_job.id} does not exist. Err: {e}", stack_info=True)

    logger.info("finished remove_old_jobs")
    return num_jobs_to_delete


@shared_task(base=FailureLoggedTask)
def refresh_cache(python_class_str: str):
    from django.utils.module_loading import import_string

    logger.info(f"Refreshing cache for {python_class_str}")
    python_class = import_string(python_class_str)

    python_class.delete_class_cache_keys()
    from api_app.models import PythonConfig

    if issubclass(python_class, PythonConfig):
        for config in python_class.objects.all():
            config.refresh_cache_keys()


@shared_task(base=FailureLoggedTask, soft_time_limit=120)
def check_stuck_analysis(minutes_ago: int = 25, check_pending: bool = False):
    """
    In case the analysis is stuck for whatever reason,
    we should force the status "failed"
    to avoid special exceptions,
    we can just put this function as a cron to cleanup.
    """
    from api_app.models import Job

    def fail_job(job):
        logger.error(
            f"found stuck analysis, job_id:{job.id}.Setting the job to status {Job.STATUSES.FAILED.value}'"
        )
        job.status = Job.STATUSES.FAILED.value
        job.finished_analysis_time = now()
        job.save(update_fields=["status", "finished_analysis_time"])

    logger.info("started check_stuck_analysis")
    running_jobs = Job.objects.running(check_pending=check_pending, minutes_ago=minutes_ago)
    logger.info(f"checking if {running_jobs.count()} jobs are stuck")

    jobs_id_stuck = []
    for running_job in running_jobs:
        jobs_id_stuck.append(running_job.id)
        if running_job.status == Job.STATUSES.RUNNING.value:
            fail_job(running_job)
        elif running_job.status == Job.STATUSES.PENDING.value:
            # the job can be pending for 2 cycles of this function
            if running_job.received_request_time < (
                now() - datetime.timedelta(minutes=(minutes_ago * 2) + 1)
            ):
                # if it's still pending, we are killing
                fail_job(running_job)
            # the job is pending for 1 cycle
            elif running_job.received_request_time < (now() - datetime.timedelta(minutes=minutes_ago)):
                logger.info(f"Running again job {running_job}")
                # we are trying to execute again all pending
                # (and technically, but it is not the case here) all failed reports
                running_job.retry()

    logger.info("finished check_stuck_analysis")

    return jobs_id_stuck


@shared_task(base=FailureLoggedTask, soft_time_limit=150)
def update(python_module_pk: int):
    from api_app.models import PythonModule
    from intel_owl.celery import broadcast

    python_module: PythonModule = PythonModule.objects.get(pk=python_module_pk)
    if settings.NFS:
        update_plugin(None, python_module_pk)
    else:
        queues = {config.queue for config in python_module.configs}
        for queue in queues:
            broadcast(
                update_plugin,
                queue=queue,
                arguments={"python_module_pk": python_module_pk},
            )


@shared_task(base=FailureLoggedTask, soft_time_limit=30)
def health_check(python_module_pk: int, plugin_config_pk: str):
    from api_app.classes import Plugin
    from api_app.models import PythonConfig, PythonModule

    plugin_class: typing.Type[Plugin] = PythonModule.objects.get(pk=python_module_pk).python_class

    config: PythonConfig = plugin_class.config_model.objects.get(pk=plugin_config_pk)
    plugin = plugin_class(
        config=config,
    )
    if not config.disabled:
        try:
            enabled = plugin.health_check(user=None)
        except NotImplementedError:
            logger.error(f"Unable to check healthcheck for {config.name}")
        else:
            config.health_check_status = enabled
            config.save()
    else:
        logger.info(f"Skipping health_check for configuration {config.name} because disabled")


@shared_task(base=FailureLoggedTask, soft_time_limit=100)
def update_notifications_with_releases():
    from django.core import management

    management.call_command(
        "changelog_notification",
        ".github/CHANGELOG.md",
        "INTELOWL",
        "--number-of-releases",
        "1",
    )


@app.task(name="job_set_final_status", soft_time_limit=30)
def job_set_final_status(job_id: int):
    from api_app.models import Job
    from api_app.websocket import JobConsumer

    job = Job.objects.get(pk=job_id)
    # execute some callbacks
    job.set_final_status()
    JobConsumer.serialize_and_send_job(job)


@shared_task(base=FailureLoggedTask, name="job_set_pipeline_status", soft_time_limit=30)
def job_set_pipeline_status(job_id: int, status: str):
    from api_app.models import Job

    job = Job.objects.get(pk=job_id)
    if status not in Status.running_statuses() + Status.partial_statuses():
        logger.error(f"Unable to set job status to {status}")
    else:
        job.status = status
        job.save(update_fields=["status"])


@shared_task(base=FailureLoggedTask, name="job_pipeline", soft_time_limit=100)
def job_pipeline(
    job_id: int,
):
    from api_app.models import Job

    job = Job.objects.get(pk=job_id)
    try:
        job.execute()
    except Exception as e:
        logger.exception(e)
        for report in (
            list(job.analyzerreports.all())
            + list(job.connectorreports.all())
            + list(job.pivotreports.all())
            + list(job.visualizerreports.all())
        ):
            report.status = report.STATUSES.FAILED.value
            report.save()


@shared_task(base=FailureLoggedTask, name="run_plugin", soft_time_limit=500)
def run_plugin(
    job_id: int,
    python_module_pk: int,
    plugin_config_pk: str,
    runtime_configuration: dict,
    task_id: int,
):
    from api_app.classes import Plugin
    from api_app.models import Job, PythonModule
    from api_app.websocket import JobConsumer

    logger.info(f"Configuring plugin {plugin_config_pk} for job {job_id} with task {task_id}")
    plugin_class: typing.Type[Plugin] = PythonModule.objects.get(pk=python_module_pk).python_class
    config = plugin_class.config_model.objects.get(pk=plugin_config_pk)
    plugin = plugin_class(
        config=config,
    )
    logger.info(f"Starting plugin {plugin_config_pk} for job {job_id} with task {task_id}")
    try:
        plugin.start(
            job_id=job_id,
            runtime_configuration=runtime_configuration,
            task_id=task_id,
        )
    except Exception as e:
        logger.exception(e)
        config.reports.filter(job__pk=job_id).update(status=plugin.report_model.STATUSES.FAILED.value)
    job = Job.objects.get(pk=job_id)
    JobConsumer.serialize_and_send_job(job)


@shared_task(base=FailureLoggedTask, name="create_caches", soft_time_limit=200)
def create_caches(user_pk: int):
    # we create the cache hit
    from certego_saas.apps.user.models import User

    user = User.objects.get(pk=user_pk)
    from api_app.analyzers_manager.models import AnalyzerConfig
    from api_app.analyzers_manager.serializers import AnalyzerConfigSerializer
    from api_app.connectors_manager.models import ConnectorConfig
    from api_app.connectors_manager.serializers import ConnectorConfigSerializer
    from api_app.ingestors_manager.models import IngestorConfig
    from api_app.ingestors_manager.serializers import IngestorConfigSerializer
    from api_app.pivots_manager.models import PivotConfig
    from api_app.pivots_manager.serializers import PivotConfigSerializer
    from api_app.serializers.plugin import PythonConfigListSerializer
    from api_app.visualizers_manager.models import VisualizerConfig
    from api_app.visualizers_manager.serializers import VisualizerConfigSerializer

    for python_config_class, serializer_class in [
        (AnalyzerConfig, AnalyzerConfigSerializer),
        (ConnectorConfig, ConnectorConfigSerializer),
        (PivotConfig, PivotConfigSerializer),
        (VisualizerConfig, VisualizerConfigSerializer),
        (IngestorConfig, IngestorConfigSerializer),
    ]:
        for plugin in python_config_class.objects.all():
            PythonConfigListSerializer(child=serializer_class()).to_representation_single_plugin(plugin, user)


@signals.beat_init.connect
def beat_init_connect(*args, sender: Consumer = None, **kwargs):
    from certego_saas.models import User

    logger.info("Starting beat_init signal")
    # update of plugins that needs it
    for task in PeriodicTask.objects.filter(enabled=True, task=f"{update.__module__}.{update.__name__}"):
        python_module_pk = json.loads(task.kwargs)["python_module_pk"]
        logger.info(f"Updating {python_module_pk}")
        update.apply_async(
            queue=get_queue_name(settings.DEFAULT_QUEUE),
            MessageGroupId=str(uuid.uuid4()),
            args=[python_module_pk],
        )

    # creating cache excluding system users
    for user in User.objects.exclude(email=""):
        logger.info(f"Creating cache for user {user.username}")
        create_caches.apply_async(
            queue=get_queue_name(settings.DEFAULT_QUEUE),
            MessageGroupId=str(uuid.uuid4()),
            args=[user.pk],
        )


@shared_task(base=FailureLoggedTask, name="send_bi_to_elastic", soft_time_limit=300)
def send_bi_to_elastic(max_timeout: int = 60, max_objects: int = 10000):
    from api_app.analyzers_manager.models import AnalyzerReport
    from api_app.connectors_manager.models import ConnectorReport
    from api_app.ingestors_manager.models import IngestorReport
    from api_app.models import AbstractReport, Job
    from api_app.pivots_manager.models import PivotReport
    from api_app.visualizers_manager.models import VisualizerReport

    if settings.ELASTICSEARCH_BI_ENABLED:
        for report_class in [
            AnalyzerReport,
            ConnectorReport,
            PivotReport,
            IngestorReport,
            VisualizerReport,
        ]:
            report_class: typing.Type[AbstractReport]
            report_class.objects.filter(sent_to_bi=False).filter_completed().defer("report").order_by(
                "-start_time"
            )[:max_objects].send_to_elastic_as_bi(max_timeout=max_timeout)
        Job.objects.filter(sent_to_bi=False).filter_completed().order_by("-received_request_time")[
            :max_objects
        ].send_to_elastic_as_bi(max_timeout=max_timeout)


@shared_task(base=FailureLoggedTask, name="send_plugin_report_to_elastic", soft_time_limit=300)
def send_plugin_report_to_elastic(max_timeout: int = 60, max_objects: int = 10000):
    from api_app.analyzers_manager.models import AnalyzerReport
    from api_app.connectors_manager.models import ConnectorReport
    from api_app.models import AbstractReport
    from api_app.pivots_manager.models import PivotReport

    if settings.ELASTICSEARCH_DSL_ENABLED and settings.ELASTICSEARCH_DSL_HOST:
        upper_threshold = now().replace(second=0, microsecond=0)
        lower_threshold = upper_threshold - datetime.timedelta(minutes=1)
        logger.info(f"add to elastic reports from: {lower_threshold} to {upper_threshold}")

        def _convert_report_to_elastic_document(
            _class: AbstractReport,
            start_time: datetime.datetime,
            end_time: datetime.datetime,
        ) -> List[Dict]:
            report_list: list(AbstractReport) = _class.objects.filter(
                status__in=ReportStatus.final_statuses(),
                end_time__gte=start_time,
                end_time__lt=end_time,
            )
            report_document_list = [
                {
                    "_op_type": "index",
                    "_index": (
                        "plugin-report-"
                        f"{get_environment()}-"
                        f"{inflection.underscore(_class.__name__).replace('_', '-')}-"
                        f"{now().date()}"
                    ),
                    "_source": {
                        "user": {"username": report.user.username},
                        "membership": (
                            {
                                "is_owner": report.user.membership.is_owner,
                                "is_admin": report.user.membership.is_admin,
                                "organization": {
                                    "name": report.user.membership.organization.name,
                                },
                            }
                            if report.user.has_membership()
                            else {}
                        ),
                        "config": {
                            "name": report.config.name,
                            "plugin_name": report.config.plugin_name.lower(),
                        },
                        "job": {"id": report.job.id},
                        "start_time": report.start_time,
                        "end_time": report.end_time,
                        "status": report.status,
                        "report": report.report,
                        "errors": report.errors,
                    },
                }
                for report in report_list
            ]
            logger.info(f"{_class.__name__} has {len(report_document_list)} new documents to upload")
            return report_document_list

        # Add document. Remove ingestors and visualizers because they contain data useless in term of search functionality:
        # ingestors contain samples and visualizers data about organizing the info inside the page.
        all_report_document_list = (
            _convert_report_to_elastic_document(AnalyzerReport, lower_threshold, upper_threshold)
            + _convert_report_to_elastic_document(ConnectorReport, lower_threshold, upper_threshold)
            + _convert_report_to_elastic_document(PivotReport, lower_threshold, upper_threshold)
        )
        logger.info(f"Documents to add to elastic: {len(all_report_document_list)}")
        if all_report_document_list:
            logger.info(
                ", ".join(
                    [
                        f"{document['_source']['job']['id']}-{document['_source']['config']['name']}"
                        for document in all_report_document_list
                    ]
                )
            )
            _, errors = bulk(  # noqa
                settings.ELASTICSEARCH_DSL_CLIENT,
                all_report_document_list,
                raise_on_error=False,
                stats_only=False,
            )
            if not errors:
                logger.info("Documents correctly inserted!")
            else:
                logger.error(f"Errors on document indexing: {errors}")
        else:
            logger.info("No documents to add")


@shared_task(
    base=FailureLoggedTask,
    name="enable_configuration_for_org_for_rate_limit",
    soft_time_limit=30,
)
def enable_configuration_for_org_for_rate_limit(org_configuration_pk: int):
    from api_app.models import OrganizationPluginConfiguration

    opc: OrganizationPluginConfiguration = OrganizationPluginConfiguration.objects.get(
        pk=org_configuration_pk
    )
    opc.enable()


# set logger
@signals.setup_logging.connect
def config_loggers(*args, **kwags):
    from logging.config import dictConfig

    dictConfig(settings.LOGGING)
