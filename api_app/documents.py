# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from django_elasticsearch_dsl import Document, fields
from django_elasticsearch_dsl.registries import registry

from .models import Job

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
    is_sample = fields.BooleanField()
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
            "received_request_time",
            "finished_analysis_time",
            "process_time",
        ]
