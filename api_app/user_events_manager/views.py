import ipaddress
import re
from http import HTTPStatus

from django.db import IntegrityError
from django.db.models import GenericIPAddressField
from django.db.models.functions import Cast
from requests import Request
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.mixins import (
    CreateModelMixin,
    DestroyModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
    UpdateModelMixin,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.filters import (
    UserAnalyzableEventFilterSet,
    UserDomainWildCardEventFilterSet,
    UserEventFilterSet,
    UserIPWildCardEventFilterSet,
)
from api_app.user_events_manager.models import (
    UserAnalyzableEvent,
    UserDomainWildCardEvent,
    UserIPWildCardEvent,
)
from api_app.user_events_manager.serializers import (
    UserAnalyzableEventSerializer,
    UserDomainWildCardEventSerializer,
    UserIPWildCardEventSerializer,
)
from certego_saas.apps.organization.permissions import (
    IsObjectOwnerOrSameOrgPermission,
    IsObjectOwnerPermission,
)


class UserEventViewSet(
    CreateModelMixin,
    RetrieveModelMixin,
    DestroyModelMixin,
    ListModelMixin,
    UpdateModelMixin,
    GenericViewSet,
):
    permission_classes = [IsAuthenticated, IsObjectOwnerOrSameOrgPermission]
    filterset_class = UserEventFilterSet

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(IsObjectOwnerPermission())
        return permissions

    def get_queryset(self):
        return super().get_queryset().visible_for_user(user=self.request.user)

    def create(self, request: Request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except IntegrityError:
            return Response(status=HTTPStatus.CONFLICT.value)


class UserAnalyzableEventViewSet(UserEventViewSet):
    queryset = UserAnalyzableEvent.objects.all()
    serializer_class = UserAnalyzableEventSerializer
    filterset_class = UserAnalyzableEventFilterSet


class UserDomainWildCardEventViewSet(UserEventViewSet):
    queryset = UserDomainWildCardEvent.objects.all()
    serializer_class = UserDomainWildCardEventSerializer
    filterset_class = UserDomainWildCardEventFilterSet

    @action(detail=False, methods=["put"])
    def validate(self, request):
        if "query" not in request.data:
            raise ValidationError({"detail": "query is required"})
        query = request.data["query"]

        try:
            re.compile(query)
        except re.error:
            raise ValidationError({"detail": "Invalid domain query"})

        return Response(
            status=HTTPStatus.OK.value,
            data=Analyzable.objects.filter(
                name__iregex=query,
                classification__in=[
                    Classification.URL.value,
                    Classification.DOMAIN.value,
                ],
            ).values_list("name", flat=True),
        )


class UserIPWildCardEventViewSet(UserEventViewSet):
    queryset = UserIPWildCardEvent.objects.all()
    serializer_class = UserIPWildCardEventSerializer
    filterset_class = UserIPWildCardEventFilterSet

    @action(detail=False, methods=["put"])
    def validate(self, request):
        if "network" not in request.data:
            raise ValidationError({"detail": "network is required"})
        network = request.data["network"]

        try:
            network = ipaddress.IPv4Network(network)
        except ValueError:
            raise ValidationError({"detail": "Invalid network"})

        return Response(
            status=HTTPStatus.OK.value,
            data=Analyzable.objects.filter(classification=Classification.IP.value)
            .annotate(ip=Cast("name", GenericIPAddressField()))
            .filter(ip__gte=str(network[0]), ip__lte=str(network[-1]))
            .values_list("name", flat=True),
        )
