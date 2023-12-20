from typing import Type

from api_app.queryset import AbstractReportQuerySet
from api_app.visualizers_manager.serializers import VisualizerReportBISerializer


class VisualizerReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_serializer_class(cls) -> Type[VisualizerReportBISerializer]:
        return VisualizerReportBISerializer
