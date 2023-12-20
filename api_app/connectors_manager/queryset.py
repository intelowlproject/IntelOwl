from typing import Type

from api_app.connectors_manager.serializers import ConnectorReportBISerializer
from api_app.queryset import AbstractReportQuerySet


class ConnectorReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_serializer_class(cls) -> Type[ConnectorReportBISerializer]:
        return ConnectorReportBISerializer
