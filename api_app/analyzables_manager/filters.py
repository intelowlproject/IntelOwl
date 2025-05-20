import rest_framework_filters as filters
from django_filters.widgets import QueryArrayWidget

from api_app.analyzables_manager.models import Analyzable


class CharInFilter(filters.BaseInFilter, filters.CharFilter):
    pass


class AnalyzableFilter(filters.FilterSet):
    name = CharInFilter(widget=QueryArrayWidget)

    class Meta:
        model = Analyzable
        fields = {
            "discovery_date": ["lte", "gte"],
        }
