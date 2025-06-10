import ipaddress
from http import HTTPStatus

from django.db import IntegrityError
from requests import Request
from rest_framework.decorators import action
from rest_framework.mixins import (
    CreateModelMixin,
    DestroyModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from api_app.analyzables_manager.models import Analyzable
from api_app.choices import Classification
from api_app.user_events_manager.filters import UserEventFilterSet
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
    GenericViewSet,
):
    permission_classes = [IsAuthenticated, IsObjectOwnerOrSameOrgPermission]
    filterset_class = UserEventFilterSet

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy"]:
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


class UserDomainWildCardEventViewSet(UserEventViewSet):
    queryset = UserDomainWildCardEvent.objects.all()
    serializer_class = UserDomainWildCardEventSerializer

    @action(detail=False, methods=["put"])
    def validate(self, request):
        query = request.PATCH.get("query")

        return Response(
            status=HTTPStatus.OK.value,
            data=[
                Analyzable.objects.filter(
                    name__iregex=query,
                    classification__in=[
                        Classification.URL.value,
                        Classification.DOMAIN.value,
                    ],
                ).values_list("name", flat=True)
            ],
        )


class UserIPWildCardEventViewSet(UserEventViewSet):
    queryset = UserIPWildCardEvent.objects.all()
    serializer_class = UserIPWildCardEventSerializer

    @action(detail=False, methods=["put"])
    def validate(self, request):
        network = request.PATCH.get("network")
        network = ipaddress.IPv4Network(network)

        return Response(
            status=HTTPStatus.OK.value,
            data=[
                Analyzable.objects.filter(
                    name__gte=network[0],
                    name__lte=network[-1],
                    classification=Classification.IP.value,
                ).values_list("name", flat=True)
            ],
        )
