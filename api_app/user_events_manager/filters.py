import rest_framework_filters as filters

from api_app.user_events_manager.models import UserEvent


class UserEventFilterSet(filters.FilterSet):

    username = filters.CharFilter(lookup_expr="iexact", field_name="user__username")
    next_decay = filters.DateRangeFilter()
    id = filters.CharFilter(method="filter_for_id")

    class Meta:
        model = UserEvent
        fields = {
            "date": ["lte", "gte"],
        }

    @staticmethod
    def filter_for_id(queryset, value, _id, *args, **kwargs):
        try:
            int_id = int(_id)
        except ValueError:
            # this is to manage bad data as input
            return queryset
        else:
            return queryset.filter(id=int_id)


class UserAnalyzableEventFilterSet(UserEventFilterSet):
    analyzable_name = filters.CharFilter(
        field_name="analyzable__name", lookup_expr="icontains"
    )


class UserDomainWildCardEventFilterSet(UserEventFilterSet):
    query = filters.CharFilter(field_name="query", lookup_expr="icontains")
    analyzables = filters.BaseInFilter(field_name="analyzables__name")


class UserIPWildCardEventFilterSet(UserEventFilterSet):
    ip = filters.CharFilter(method="filter_for_ip", lookup_expr="icontains")
    analyzables = filters.BaseInFilter(field_name="analyzables__name")

    @staticmethod
    def filter_for_ip(queryset, value, user, *args, **kwargs):
        return queryset.filter(start_ip__lte=value, end_ip__gte=value)
