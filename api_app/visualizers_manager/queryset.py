from typing import TYPE_CHECKING, Type

from api_app.queryset import AbstractReportQuerySet

if TYPE_CHECKING:
    from api_app.visualizers_manager.serializers import VisualizerReportBISerializer


class VisualizerReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_bi_serializer_class(cls) -> Type["VisualizerReportBISerializer"]:
        from api_app.visualizers_manager.serializers import VisualizerReportBISerializer

        return VisualizerReportBISerializer
