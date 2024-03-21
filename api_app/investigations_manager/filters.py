import rest_framework_filters as filters

from api_app.investigations_manager.models import Investigation


class InvestigationFilter(filters.FilterSet):
    class Meta:
        model = Investigation
        fields = {
            "start_time": ["lte", "gte"],
            "end_time": ["lte", "gte"],
            "status": ["exact"],
        }
