from typing import TYPE_CHECKING, Type

from api_app.queryset import AbstractReportQuerySet

if TYPE_CHECKING:
    from api_app.analyzers_manager.serializers import AnalyzerReportBISerializer


class AnalyzerReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_bi_serializer_class(cls) -> Type["AnalyzerReportBISerializer"]:
        from api_app.analyzers_manager.serializers import AnalyzerReportBISerializer

        return AnalyzerReportBISerializer
