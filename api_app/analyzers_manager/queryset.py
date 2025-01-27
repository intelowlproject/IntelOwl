from typing import TYPE_CHECKING, Type

from django.db.models import QuerySet

from api_app.queryset import AbstractReportQuerySet

if TYPE_CHECKING:
    from api_app.analyzers_manager.serializers import AnalyzerReportBISerializer


class AnalyzerReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_bi_serializer_class(cls) -> Type["AnalyzerReportBISerializer"]:
        from api_app.analyzers_manager.serializers import AnalyzerReportBISerializer

        return AnalyzerReportBISerializer

    def get_data_models(self, job) -> QuerySet:
        DataModel = job.analyzable.get_data_model_class()  # noqa
        return DataModel.objects.filter(
            pk__in=self.values_list("data_model_object_id", flat=True)
        )
