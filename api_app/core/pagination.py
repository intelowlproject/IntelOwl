from rest_framework.pagination import PageNumberPagination


class IncreasedSizeResultsSetPagination(PageNumberPagination):
    page_size = 100
