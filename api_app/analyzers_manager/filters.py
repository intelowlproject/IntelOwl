import rest_framework_filters as filters

from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.fields import ChoiceArrayField


class AnalyzerConfigFilter(filters.FilterSet):
    class Meta:
        model = AnalyzerConfig
        filter_overrides = {
            ChoiceArrayField: {
                "filter_class": filters.ChoiceFilter,
            }
        }
        fields = {"type": ["exact"], "observable_supported": ["in"]}
