import ipaddress

import rest_framework_filters as filters
from django.contrib.contenttypes.models import ContentType

from api_app.data_model_manager.models import (
    DomainDataModel,
    FileDataModel,
    IPDataModel,
)
from api_app.user_events_manager.models import UserAnalyzableEvent, UserEvent


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
    analyzable_name = filters.CharFilter(field_name="analyzable__name", lookup_expr="icontains")
    event_date__gte = filters.CharFilter(method="filter_for_event_date")
    event_date__lte = filters.CharFilter(method="filter_for_event_date")

    @staticmethod
    def filter_for_event_date(queryset, value, _date, *args, **kwargs):
        date_filters = {}
        if value.endswith("__gte"):
            date_filters["date__gte"] = _date
        if value.endswith("__lte"):
            date_filters["date__lte"] = _date

        data_model_map = {
            DomainDataModel: ContentType.objects.get_for_model(DomainDataModel),
            IPDataModel: ContentType.objects.get_for_model(IPDataModel),
            FileDataModel: ContentType.objects.get_for_model(FileDataModel),
        }

        user_events_ids = []
        for model, content_type in data_model_map.items():
            data_model_ids = model.objects.filter(**date_filters).values_list("id", flat=True)
            if data_model_ids:
                ids = UserAnalyzableEvent.objects.filter(
                    data_model_content_type=content_type,
                    data_model_object_id__in=data_model_ids,
                ).values_list("id", flat=True)
                user_events_ids.extend(ids)

        return queryset.filter(id__in=user_events_ids)


class UserDomainWildCardEventFilterSet(UserEventFilterSet):
    query = filters.CharFilter(field_name="query", lookup_expr="icontains")
    analyzables = filters.BaseInFilter(field_name="analyzables__name")
    event_date__gte = filters.CharFilter(field_name="data_model__date", lookup_expr="gte")
    event_date__lte = filters.CharFilter(field_name="data_model__date", lookup_expr="lte")


class UserIPWildCardEventFilterSet(UserEventFilterSet):
    ip = filters.CharFilter(method="filter_for_ip", lookup_expr="icontains")
    network = filters.CharFilter(method="filter_for_network")
    analyzables = filters.BaseInFilter(field_name="analyzables__name")
    event_date__gte = filters.CharFilter(field_name="data_model__date", lookup_expr="gte")
    event_date__lte = filters.CharFilter(field_name="data_model__date", lookup_expr="lte")

    @staticmethod
    def filter_for_ip(queryset, value, _ip, *args, **kwargs):
        return queryset.filter(start_ip__lte=_ip, end_ip__gte=_ip)

    @staticmethod
    def filter_for_network(queryset, value, _network, *args, **kwargs):
        network = ipaddress.IPv4Network(_network)
        start_ip = str(network[0])
        end_ip = str(network[-1])
        return queryset.filter(start_ip=start_ip, end_ip=end_ip)
