# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from drf_spectacular.utils import extend_schema as add_docs
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api_app.playbooks_manager.models import PlaybookConfig
from api_app.playbooks_manager.serializers import PlaybookConfigSerializer
from api_app.serializers.job import (
    FileJobSerializer,
    JobResponseSerializer,
    ObservableAnalysisSerializer,
)
from api_app.views import AbstractConfigViewSet, ModelWithOwnershipViewSet

logger = logging.getLogger(__name__)


class PlaybookConfigViewSet(
    ModelWithOwnershipViewSet, AbstractConfigViewSet, mixins.CreateModelMixin
):
    serializer_class = PlaybookConfigSerializer
    ordering = ["-weight", "-executed_by_pivot", "name"]
    permission_classes = [IsAuthenticated]
    queryset = PlaybookConfig.objects.all()

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .ordered_for_user(self.request.user)
            .prefetch_related(
                "analyzers",
                "connectors",
                "pivots",
                "visualizers",
                "tags",
            )
        )

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
        request=FileJobSerializer,
        responses={200: JobResponseSerializer},
    )
    @action(methods=["POST"], url_name="analyze_multiple_files", detail=False)
    def analyze_multiple_files(self, request):
        oas = FileJobSerializer(
            data=request.data, many=True, context={"request": request}
        )
        oas.is_valid(raise_exception=True)
        jobs = oas.save(send_task=True)
        return Response(
            JobResponseSerializer(jobs, many=True).data,
            status=status.HTTP_200_OK,
        )
