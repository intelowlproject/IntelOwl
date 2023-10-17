# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import rest_framework_filters as filters
from django.db.models import Q

from .analyzers_manager.constants import ObservableTypes
from .models import Job

__all__ = [
    "JobFilter",
]


class JobFilter(filters.FilterSet):
    is_sample = filters.BooleanFilter()
    md5 = filters.CharFilter(lookup_expr="icontains")
    observable_name = filters.CharFilter(lookup_expr="icontains")
    file_name = filters.CharFilter(lookup_expr="icontains")
    file_mimetype = filters.CharFilter(lookup_expr="icontains")
    tags = filters.BaseInFilter(field_name="tags__label", lookup_expr="in")
    playbook_to_execute = filters.CharFilter(
        field_name="playbook_to_execute__name", lookup_expr="icontains"
    )

    # extra
    user = filters.CharFilter(method="filter_for_user")
    id = filters.CharFilter(method="filter_for_id")
    type = filters.CharFilter(method="filter_for_type")
    name = filters.CharFilter(method="filter_for_name")

    @staticmethod
    def filter_for_user(queryset, value, user, *args, **kwargs):
        return queryset.filter(user__username__icontains=user)

    @staticmethod
    def filter_for_id(queryset, value, _id, *args, **kwargs):
        try:
            int_id = int(_id)
        except ValueError:
            # this is to manage bad data as input
            return queryset
        else:
            return queryset.filter(id=int_id)

    @staticmethod
    def filter_for_type(queryset, value, _type, *args, **kwargs):
        if _type in ObservableTypes.values:
            return queryset.filter(observable_classification=_type)
        return queryset.filter(file_mimetype__icontains=_type)

    @staticmethod
    def filter_for_name(queryset, value, name, *args, **kwargs):
        return queryset.filter(
            Q(observable_name__icontains=name) | Q(file_name__icontains=name)
        )

    class Meta:
        model = Job
        fields = {
            "received_request_time": ["lte", "gte"],
            "finished_analysis_time": ["lte", "gte"],
            "observable_classification": ["exact"],
            "tlp": ["exact"],
            "status": ["exact"],
        }
