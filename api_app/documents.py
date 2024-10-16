# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import json
import logging

import inflection
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django_elasticsearch_dsl import Document, Index, fields
from django_elasticsearch_dsl.registries import registry
from elasticsearch import ApiError
from elasticsearch_dsl import connections

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.choices import ReportStatus

# from api_app.connectors_manager.models import ConnectorReport
# from api_app.ingestors_manager.models import IngestorReport
from api_app.models import AbstractReport

from .models import Job

# from api_app.pivots_manager.models import PivotReport
# from api_app.visualizers_manager.models import VisualizerReport


logger = logging.getLogger(__name__)


@registry.register_document  # TODO: maybe we can replace this with the signal and remove django elasticsearch dsl
class JobDocument(Document):
    # Object/List fields
    analyzers_to_execute = fields.NestedField(
        properties={"name": fields.KeywordField()}
    )
    connectors_to_execute = fields.NestedField(
        properties={"name": fields.KeywordField()}
    )
    visualizers_to_execute = fields.NestedField(
        properties={"name": fields.KeywordField()}
    )
    playbook_to_execute = fields.ObjectField(
        properties={
            "name": fields.KeywordField(),
        },
    )

    # Normal fields
    errors = fields.TextField()
    # Keyword fields to allow aggregations/vizualizations
    source = fields.KeywordField()
    status = fields.KeywordField()
    md5 = fields.KeywordField()
    tlp = fields.KeywordField()
    observable_name = fields.KeywordField()
    observable_classification = fields.KeywordField()
    file_name = fields.KeywordField()
    file_mimetype = fields.KeywordField()
    # Nested (ForeignKey) fields
    tags = fields.NestedField(
        properties={"label": fields.KeywordField(), "color": fields.TextField()}
    )
    analyzerreports = fields.NestedField(
        properties={
            "name": fields.KeywordField(),
            "status": fields.KeywordField(),
            "report": fields.ObjectField(),
            "errors": fields.TextField(),
            "start_time": fields.DateField(),
            "end_time": fields.DateField(),
        }
    )
    connector_reports = fields.NestedField(
        properties={
            "name": fields.KeywordField(),
            "status": fields.KeywordField(),
            "report": fields.ObjectField(),
            "errors": fields.TextField(),
            "start_time": fields.DateField(),
            "end_time": fields.DateField(),
        }
    )

    class Index:
        # Name of the Elasticsearch index
        name = "jobs"

    class Django:
        model = Job  # The model associated with this Document

        # The fields of the model you want to be indexed in Elasticsearch
        fields = [
            "is_sample",
            "received_request_time",
            "finished_analysis_time",
            "process_time",
        ]


@receiver(post_save, sender=AnalyzerReport)
# @receiver(post_save, sender=ConnectorReport)
# @receiver(post_save, sender=PivotReport)
# @receiver(post_save, sender=IngestorReport)
# @receiver(post_save, sender=VisualizerReport)
def plugin_report_save_signal_listener(sender, **kwargs):
    logger.debug(f"{sender=} {sender.__name__} {type(sender.__name__)}")
    logger.debug(f"{kwargs=}")
    report: AbstractReport = kwargs["instance"]
    logger.debug(f"{report.status=}")
    if report.status in ReportStatus.final_statuses():
        document_data = {
            "config": {"name": report.config.name},
            "job": {"id": report.job.id},
            "start_time": report.start_time,
            "end_time": report.end_time,
            "status": report.status,
            "report": report.report,
        }
        logger.debug(f"{document_data=}")
        PluginReportElastic.add_document(
            # elasticsearch_dsl wants idexes in lowercase, also we use dash case
            plugin_report_name=sender.__name__,
            document_data=document_data,
        )


class PluginReportElastic:

    @staticmethod
    def add_document(plugin_report_name: str, document_data: dict) -> bool:
        index_name = f"plugin-report-{inflection.underscore(plugin_report_name).replace('_', '-')}-{datetime.date.today()}"
        # check if index exist or create it
        if Index(index_name).exists():
            logger.info(f"index {index_name} already exist, do nothing.")
        else:
            try:
                with open(
                    settings.CONFIG_ROOT
                    / "elastic_search_mappings"
                    / "plugin_report.json"
                ) as file_content:
                    body = json.load(file_content)
                    connections.get_connection().indices.put_template(
                        name="plugin-report", body=body
                    )
                    logger.info(
                        "created/updated template for plugin report for Elastic named"
                    )
            except ApiError as error:
                logger.critical(error)
        # add document
        try:
            connections.get_connection().index(index=index_name, body=document_data)
        except ApiError as error:
            logger.critical(error)
