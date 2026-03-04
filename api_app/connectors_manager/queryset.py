from typing import TYPE_CHECKING, Type

from api_app.queryset import AbstractReportQuerySet

if TYPE_CHECKING:
    from api_app.connectors_manager.serializers import ConnectorReportBISerializer


class ConnectorReportQuerySet(AbstractReportQuerySet):
    """QuerySet for ConnectorReport model with BI serializer support."""

    @classmethod
    def _get_bi_serializer_class(cls) -> Type["ConnectorReportBISerializer"]:
        from api_app.connectors_manager.serializers import ConnectorReportBISerializer

        return ConnectorReportBISerializer
