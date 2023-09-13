# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from drf_spectacular.utils import extend_schema as add_docs
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api_app.playbooks_manager.serializers import PlaybookConfigSerializer
from api_app.serializers import (
    FileAnalysisSerializer,
    JobResponseSerializer,
    ObservableAnalysisSerializer,
)
from api_app.views import AbstractConfigViewSet

logger = logging.getLogger(__name__)


class PlaybookConfigViewSet(AbstractConfigViewSet, mixins.CreateModelMixin):
    serializer_class = PlaybookConfigSerializer
    ordering = ["-weight", "name"]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return self.serializer_class.Meta.model.objects.ordered_for_user(
            self.request.user
        ).prefetch_related("analyzers", "connectors", "visualizers", "tags", "pivots")

    @add_docs(
        description="This endpoint allows to start a Job related to an observable",
        request=ObservableAnalysisSerializer,
        responses={200: JobResponseSerializer},
    )
    @action(methods=["POST"], url_name="analyze_multiple_observables", detail=False)
    def analyze_multiple_observables(self, request):
        oas = ObservableAnalysisSerializer(
            data=request.data, many=True, context={"request": request}
        )
        oas.is_valid(raise_exception=True)
        jobs = oas.save(send_task=True)
        return Response(
            JobResponseSerializer(jobs, many=True).data,
            status=status.HTTP_200_OK,
        )

    @add_docs(
        description="This endpoint allows to start a Job related to a file",
        request=FileAnalysisSerializer,
        responses={200: JobResponseSerializer},
    )
    @action(methods=["POST"], url_name="analyze_multiple_files", detail=False)
    def analyze_multiple_files(self, request):
        oas = FileAnalysisSerializer(
            data=request.data, many=True, context={"request": request}
        )
        oas.is_valid(raise_exception=True)
        jobs = oas.save(send_task=True)
        return Response(
            JobResponseSerializer(jobs, many=True).data,
            status=status.HTTP_200_OK,
        )
