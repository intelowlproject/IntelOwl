import rest_framework_filters as filters

from api_app.investigations_manager.models import Investigation


class InvestigationFilter(filters.FilterSet):
    name = filters.CharFilter(lookup_expr="icontains")

    owner = filters.CharFilter(method="filter_for_owner")
    id = filters.CharFilter(method="filter_for_id")
    tlp = filters.CharFilter(method="filter_for_tlp")
    tags = filters.CharFilter(method="filter_for_tags")
    analyzed_object_name = filters.CharFilter(method="filter_for_analyzed_object_name")

    @staticmethod
    def filter_for_analyzed_object_name(queryset, value, analyzed_object_name, *args, **kwargs):
        return Investigation.investigation_for_analyzable(queryset, analyzed_object_name)

    @staticmethod
    def filter_for_owner(queryset, value, owner, *args, **kwargs):
        return queryset.filter(owner__username__icontains=owner)

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
    def filter_for_tlp(queryset, value, tlp, *args, **kwargs):
        id_list = [
            investigation.id for investigation in Investigation.objects.all() if investigation.tlp == tlp
        ]
        return queryset.filter(id__in=id_list)

    @staticmethod
    def filter_for_tags(queryset, value, tags, *args, **kwargs):
        id_list = [
            investigation.id for investigation in Investigation.objects.all() if tags in investigation.tags
        ]
        return queryset.filter(id__in=id_list)

    class Meta:
        model = Investigation
        fields = {
            "start_time": ["lte", "gte"],
            "end_time": ["lte", "gte"],
            "status": ["exact"],
        }
