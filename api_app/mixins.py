import logging

from django.core.cache import cache
from rest_framework.response import Response

from certego_saas.ext.pagination import CustomPageNumberPagination

logger = logging.getLogger(__name__)


class PaginationMixin:
    pagination_class = CustomPageNumberPagination

    def list(self, request, *args, **kwargs):
        cache_name = (
            f"list_{self.serializer_class.Meta.model.__name__}_{request.user.username}"
        )
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            objects = queryset.filter(pk__in=[plugin.pk for plugin in page])
            if "page" in request.query_params and "page_size" in request.query_params:
                cache_name += (
                    f"_{request.query_params['page']}_"
                    f"{request.query_params['page_size']}"
                )
            cache_hit = cache.get(cache_name)
            if cache_hit is None:
                logger.debug(f"View {cache_name} cache not hit")
                serializer = self.get_serializer(objects, many=True)
                data = serializer.data
                cache.set(cache_name, value=data, timeout=60 * 60 * 24 * 7)
            else:
                logger.debug(f"View {cache_name} cache hit")
                data = cache_hit
                cache.touch(cache_name, timeout=60 * 60 * 24 * 7)
            return self.get_paginated_response(data)
        else:
            cache_hit = cache.get(cache_name)

            if cache_hit is None:
                serializer = self.get_serializer(queryset, many=True)
                data = serializer.data
                cache.set(cache_name, value=data, timeout=60 * 60 * 24 * 7)
            else:
                data = cache_hit
                cache.touch(cache_name, timeout=60 * 60 * 24 * 7)

        return Response(data)
