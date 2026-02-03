import datetime
import logging
from http import HTTPStatus

from django.utils import timezone
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api_app.analyzables_manager.filters import AnalyzableFilter
from api_app.analyzables_manager.models import Analyzable
from api_app.analyzables_manager.serializers import AnalyzableSerializer
from api_app.investigations_manager.models import Investigation
from api_app.serializers.job import JobAnalyzableHistorySerializer
from api_app.user_events_manager.serializers import (
    UserAnalyzableEventSerializer,
    UserDomainWildCardEventSerializer,
    UserIPWildCardEventSerializer,
)

logger = logging.getLogger(__name__)


class AnalyzableViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AnalyzableSerializer
    permission_classes = [IsAuthenticated]
    queryset = Analyzable.objects.all()
    filterset_class = AnalyzableFilter

    def get_queryset(self):
        user = self.request.user
        return super().get_queryset().visible_for_user(user)

    @action(detail=True)
    def related_investigation_number(self, request, pk=None):
        logger.debug(f"get_related_investigation_number: {pk}")
        try:
            analyzable: Analyzable = self.get_queryset().get(pk=pk)
        except Analyzable.DoesNotExist:
            raise ValidationError({"detail": "Requested analyzable does not exist."})
        logger.debug(f"{analyzable=}")
        related_investigation_number = Investigation.investigation_for_analyzable(
            Investigation.objects.filter(
                start_time__gte=timezone.now() - datetime.timedelta(days=30),
            ),
            analyzable.name,
        ).count()
        return Response(
            status=HTTPStatus.OK.value,
            data={"related_investigation_number": related_investigation_number},
        )

    @action(detail=True)
    def history(self, request, pk=None):
        user = request.user
        try:
            analyzable: Analyzable = self.get_queryset().get(pk=pk)
        except Analyzable.DoesNotExist:
            raise ValidationError({"detail": "Requested analyzable does not exist."})

        jobs_queryset = analyzable.jobs.visible_for_user(user).order_by("-finished_analysis_time")
        user_events_queryset = analyzable.user_events.visible_for_user(user).order_by("-date")
        user_domain_wildcard_events_queryset = analyzable.user_domain_wildcard_events.visible_for_user(
            user
        ).order_by("-date")
        user_ip_wildcard_events_queryset = analyzable.user_ip_wildcard_events.visible_for_user(user).order_by(
            "-date"
        )

        jobs = JobAnalyzableHistorySerializer(jobs_queryset, many=True).data
        user_events = UserAnalyzableEventSerializer(user_events_queryset, many=True).data
        user_domain_wildcard_events = UserDomainWildCardEventSerializer(
            user_domain_wildcard_events_queryset, many=True
        ).data
        user_ip_wildcard_events = UserIPWildCardEventSerializer(
            user_ip_wildcard_events_queryset, many=True
        ).data

        return Response(
            status=HTTPStatus.OK.value,
            data={
                "jobs": jobs,
                "user_events": user_events,
                "user_domain_wildcard_events": user_domain_wildcard_events,
                "user_ip_wildcard_events": user_ip_wildcard_events,
            },
        )
