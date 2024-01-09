from typing import TYPE_CHECKING, Type

from api_app.queryset import AbstractReportQuerySet

if TYPE_CHECKING:
    from api_app.ingestors_manager.serializers import IngestorReportBISerializer


class IngestorReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_bi_serializer_class(cls) -> Type["IngestorReportBISerializer"]:
        from api_app.ingestors_manager.serializers import IngestorReportBISerializer

        return IngestorReportBISerializer
