from typing import Type

from api_app.analyzers_manager.serializers import AnalyzerReportBISerializer
from api_app.queryset import AbstractReportQuerySet


class AnalyzerReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_serializer_class(cls) -> Type[AnalyzerReportBISerializer]:
        return AnalyzerReportBISerializer
