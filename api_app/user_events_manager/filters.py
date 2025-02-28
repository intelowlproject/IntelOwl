import rest_framework_filters as filters


class UserEventFilterSet(filters.FilterSet):

    username = filters.CharFilter(lookup_expr="iexact", field_name="user__username")
    next_decay = filters.DateRangeFilter()
    date = filters.DateRangeFilter()


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
