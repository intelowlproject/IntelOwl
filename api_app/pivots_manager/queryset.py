from typing import TYPE_CHECKING, Type

from django.db.models import Q

from api_app.queryset import AbstractReportQuerySet, PythonConfigQuerySet

if TYPE_CHECKING:
    from api_app.pivots_manager.serializers import PivotReportBISerializer


class PivotConfigQuerySet(PythonConfigQuerySet):
    def valid(
        self, analyzers: PythonConfigQuerySet, connectors: PythonConfigQuerySet
    ) -> "PivotConfigQuerySet":
        qs = self
        if analyzers.exists():
            qs = qs.many_to_many_to_array("related_analyzer_configs").filter(
                Q(related_analyzer_configs_array__contained_by=list(analyzers.values_list("pk", flat=True)))
            )
        if connectors.exists():
            qs = qs.many_to_many_to_array("related_connector_configs").filter(
                Q(related_connector_configs_array__contained_by=list(connectors.values_list("pk", flat=True)))
            )
        return qs.distinct()


class PivotReportQuerySet(AbstractReportQuerySet):
    @classmethod
    def _get_bi_serializer_class(cls) -> Type["PivotReportBISerializer"]:
        from api_app.pivots_manager.serializers import PivotReportBISerializer

        return PivotReportBISerializer
