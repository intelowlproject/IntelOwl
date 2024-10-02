# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django_elasticsearch_dsl import Document, fields
from django_elasticsearch_dsl.registries import registry

from api_app.analyzers_manager.models import AnalyzerReport
from api_app.connectors_manager.models import ConnectorReport
from api_app.ingestors_manager.models import IngestorReport
from api_app.pivots_manager.models import PivotReport
from api_app.visualizers_manager.models import VisualizerReport

from .models import Job


@registry.register_document
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
            # "scan_mode": fields.IntegerField()  # TODO: remove, just for testing
        },
    )
    # scan_mode = fields.IntegerField()  # TODO: remove, just for testing

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


class AbstractReportDocument(Document):

    job = fields.ObjectField(
        properties={
            "id": fields.IntegerField(),
        }
    )
    config = fields.ObjectField(
        properties={
            "name": fields.KeywordField(),
        }
    )
    report = fields.NestedField()
    errors = fields.TextField()

    class Django:
        # The fields of the model you want to be indexed in Elasticsearch
        fields = [
            "status",
            "start_time",
            "end_time",
        ]


@registry.register_document
class AnalyzerReportDocument(AbstractReportDocument):

    class Index:
        # Name of the Elasticsearch index
        name = "analyzer_reports"

    class Django:
        model = AnalyzerReport  # The model associated with this Document

        fields = AbstractReportDocument.Django.fields + []


@registry.register_document
class ConnectorReportDocument(AbstractReportDocument):

    class Index:
        # Name of the Elasticsearch index
        name = "connector_reports"

    class Django:
        model = ConnectorReport  # The model associated with this Document

        fields = AbstractReportDocument.Django.fields + []


@registry.register_document
class IngestorReportDocument(AbstractReportDocument):

    class Index:
        # Name of the Elasticsearch index
        name = "ingestor_reports"

    class Django:
        model = IngestorReport  # The model associated with this Document

        fields = AbstractReportDocument.Django.fields + []


@registry.register_document
class PivotReportDocument(AbstractReportDocument):

    class Index:
        # Name of the Elasticsearch index
        name = "pivot_reports"

    class Django:
        model = PivotReport  # The model associated with this Document

        fields = AbstractReportDocument.Django.fields + []


@registry.register_document
class VisualizerReportDocument(AbstractReportDocument):

    class Index:
        # Name of the Elasticsearch index
        name = "visualizer_reports"

    class Django:
        model = VisualizerReport  # The model associated with this Document

        fields = AbstractReportDocument.Django.fields + []
