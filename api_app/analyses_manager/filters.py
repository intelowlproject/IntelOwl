import rest_framework_filters as filters

from api_app.analyses_manager.models import Analysis


class AnalysisFilter(filters.FilterSet):
    class Meta:
        model = Analysis
        fields = {
            "start_time": ["lte", "gte"],
            "end_time": ["lte", "gte"],
            "status": ["exact"],
        }
