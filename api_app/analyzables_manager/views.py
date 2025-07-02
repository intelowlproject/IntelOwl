import logging
from http import HTTPStatus

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api_app.analyzables_manager.filters import AnalyzableFilter
from api_app.analyzables_manager.models import Analyzable
from api_app.analyzables_manager.serializers import AnalyzableSerializer
from api_app.models import Job
from api_app.serializers.job import JobAnalyzableHistorySerializer
from api_app.user_events_manager.models import UserAnalyzableEvent
from api_app.user_events_manager.serializers import UserAnalyzableEventSerializer

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
    def history(self, request, pk=None):
        response_data = {}
        try:
            jobs_queryset = Job.objects.filter(analyzable=pk).order_by(
                "-finished_analysis_time"
            )
        except Job.DoesNotExist:
            raise ValidationError({"detail": "Requested jobs does not exist."})
        finally:
            jobs = JobAnalyzableHistorySerializer(jobs_queryset, many=True).data
            response_data["jobs"] = jobs
        try:
            user_events_queryset = UserAnalyzableEvent.objects.filter(
                analyzable=pk
            ).order_by("-date")
        except UserAnalyzableEvent.DoesNotExist:
            raise ValidationError({"detail": "Requested user events does not exist."})
        finally:
            user_events = UserAnalyzableEventSerializer(
                user_events_queryset, many=True
            ).data
            response_data["user_events"] = user_events

        return Response(
            status=HTTPStatus.OK.value,
            data=response_data,
        )
