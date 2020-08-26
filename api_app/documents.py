from django_elasticsearch_dsl import Document, fields
from django_elasticsearch_dsl.registries import registry
from .models import Job


@registry.register_document
class JobDocument(Document):
    # Object/List fields
    analyzers_requested = fields.ListField(fields.KeywordField())
    analyzers_to_execute = fields.ListField(fields.KeywordField())
    analysis_reports = fields.ObjectField()
    # Normal fields
    errors = fields.TextField()
    runtime_configuration = fields.ObjectField()
    # Keyword fields to allow aggregations/vizualizations
    source = fields.KeywordField()
    md5 = fields.KeywordField()
    status = fields.KeywordField()
    observable_name = fields.KeywordField()
    observable_classification = fields.KeywordField()
    file_name = fields.KeywordField()
    file_mimetype = fields.KeywordField()
    # Nested (ForeignKey) fields
    tags = fields.NestedField(
        properties={"label": fields.KeywordField(), "color": fields.TextField()}
    )

    def prepare_runtime_configuration(self, instance):
        return instance.runtime_configuration

    def prepare_analysis_reports(self, instance):
        """
        https://github.com/django-es/django-elasticsearch-dsl/issues/36
        """
        return instance.analysis_reports

    class Index:
        # Name of the Elasticsearch index
        name = "jobs"

    class Django:
        model = Job  # The model associated with this Document

        # The fields of the model you want to be indexed in Elasticsearch
        fields = [
            "is_sample",
            "run_all_available_analyzers",
            "received_request_time",
            "finished_analysis_time",
            "force_privacy",
            "disable_external_analyzers",
        ]
