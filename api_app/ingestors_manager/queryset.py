from typing import Type

from api_app.ingestors_manager.serializers import IngestorReportBISerializer
from api_app.queryset import AbstractReportQuerySet


class IngestorReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_serializer_class(cls) -> Type[IngestorReportBISerializer]:
        return IngestorReportBISerializer
