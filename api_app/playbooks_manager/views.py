# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Union

from drf_spectacular.utils import extend_schema as add_docs
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, action
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response

from api_app.playbooks_manager.serializers import (
    PlaybookConfigCreateSerializer,
    PlaybookConfigSerializer,
)
from api_app.serializers import (
    AnalysisResponseSerializer,
    PlaybookFileAnalysisSerializer,
    PlaybookObservableAnalysisSerializer,
)
from certego_saas.ext.mixins import SerializerActionMixin

from ..views import _multi_analysis_request

logger = logging.getLogger(__name__)


class PlaybookConfigAPI(viewsets.ModelViewSet, SerializerActionMixin):

    serializer_class =  PlaybookConfigSerializer

    serializer_action_classes = {
        "create": PlaybookConfigCreateSerializer
    }

    permission_classes = [IsAuthenticated]

    def _multi_analysis_request_playbooks(
            self,
            request,
            serializer_class: Union[
                PlaybookFileAnalysisSerializer, PlaybookObservableAnalysisSerializer
            ],
    ):
        """
        Prepare and send multiple files/observables for running playbooks
        """
        response = _multi_analysis_request(
            request,
            data=request.data,
            serializer_class=serializer_class,
        )

        return Response(
            response,
            status=status.HTTP_200_OK,
        )


    def check_permissions(self, request):
        if request.method in ["DELETE", "PATCH"]:
            permission = IsAdminUser()
            if not permission.has_permission(request, self):
                self.permission_denied(
                    request,
                    message=getattr(permission, 'message', None),
                    code=getattr(permission, 'code', None)
                )
        return super().check_permissions(request)

    def get_queryset(self):
        return PlaybookConfigSerializer.Meta.model.objects.all()

    @add_docs(
        description="This endpoint allows to start a Job related to an observable",
        request=PlaybookObservableAnalysisSerializer,
        responses={200: AnalysisResponseSerializer},
    )
    @action(methods=["POST"], url_name="analyze_multiple_observables", detail=False)
    def analyze_multiple_observables(self, request):
        return self._multi_analysis_request_playbooks(
            request, PlaybookObservableAnalysisSerializer
        )

    @add_docs(
        description="This endpoint allows to start a Job related to a file",
        request=PlaybookFileAnalysisSerializer,
        responses={200: AnalysisResponseSerializer},
    )
    @action(methods=["POST"], url_name="analyze_multiple_files", detail=False)
    def analyze_multiple_files(self, request):
        return self._multi_analysis_request_playbooks(request, PlaybookFileAnalysisSerializer)