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
    """
    A filter set for the Job model, allowing for various filtering
    criteria to be applied to job queries.

    Attributes:
        is_sample (BooleanFilter): Filter by whether the job is a sample.
        md5 (CharFilter): Filter by MD5 hash, case-insensitive contains.
        observable_name (CharFilter): Filter by observable name, case-insensitive contains.
        file_name (CharFilter): Filter by file name, case-insensitive contains.
        file_mimetype (CharFilter): Filter by file MIME type, case-insensitive contains.
        tags (BaseInFilter): Filter by tags, using an 'in' lookup.
        playbook_to_execute (CharFilter): Filter by playbook name to execute, case-insensitive contains.
        user (CharFilter): Custom filter method to filter by user.
        id (CharFilter): Custom filter method to filter by job ID.
        type (CharFilter): Custom filter method to filter by type (observable classification or file MIME type).
        name (CharFilter): Custom filter method to filter by name (observable or file name).
    """

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
        """
        Filters the queryset by user.

        Args:
            queryset (QuerySet): The queryset to filter.
            value (str): The filter value.
            user (str): The username to filter by.

        Returns:
            QuerySet: The filtered queryset.
        """
        return queryset.filter(user__username__icontains=user)

    @staticmethod
    def filter_for_id(queryset, value, _id, *args, **kwargs):
        """
        Filters the queryset by job ID.

        Args:
            queryset (QuerySet): The queryset to filter.
            value (str): The filter value.
            _id (str): The job ID to filter by.

        Returns:
            QuerySet: The filtered queryset.
        """
        try:
            int_id = int(_id)
        except ValueError:
            # this is to manage bad data as input
            return queryset
        else:
            return queryset.filter(id=int_id)

    @staticmethod
    def filter_for_type(queryset, value, _type, *args, **kwargs):
        """
        Filters the queryset by observable type or file MIME type.

        Args:
            queryset (QuerySet): The queryset to filter.
            value (str): The filter value.
            _type (str): The type to filter by (observable or MIME type).

        Returns:
            QuerySet: The filtered queryset.
        """
        if _type in ObservableTypes.values:
            return queryset.filter(observable_classification=_type)
        return queryset.filter(file_mimetype__icontains=_type)

    @staticmethod
    def filter_for_name(queryset, value, name, *args, **kwargs):
        """
        Filters the queryset by observable name or file name.

        Args:
            queryset (QuerySet): The queryset to filter.
            value (str): The filter value.
            name (str): The name to filter by (observable or file name).

        Returns:
            QuerySet: The filtered queryset.
        """
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
