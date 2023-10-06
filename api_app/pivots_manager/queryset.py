from api_app.queryset import PythonConfigQuerySet


class PivotConfigQuerySet(PythonConfigQuerySet):
    def valid(
        self, analyzers: PythonConfigQuerySet, connectors: PythonConfigQuerySet
    ) -> "PivotConfigQuerySet":
        qs = self
        if analyzers.exists():
            qs = qs.many_to_many_to_array("related_analyzer_configs").filter(
                related_analyzer_configs_array__contained_by=list(
                    analyzers.values_list("pk", flat=True)
                )
            )
        if connectors.exists():
            qs = qs.many_to_many_to_array("related_connector_configs").filter(
                related_connector_configs_array__contained_by=list(
                    connectors.values_list("pk", flat=True)
                )
            )
        return qs
