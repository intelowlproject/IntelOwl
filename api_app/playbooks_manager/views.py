# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Union

from drf_spectacular.utils import extend_schema as add_docs
from rest_framework import status, viewsets
from rest_framework.decorators import api_view
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

from ..views import _multi_analysis_request

logger = logging.getLogger(__name__)


def _multi_analysis_request_playbooks(
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


@add_docs(
    description="This endpoint allows to start a Job related to a file",
    request=PlaybookFileAnalysisSerializer,
    responses={200: AnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_files(request):
    return _multi_analysis_request_playbooks(request, PlaybookFileAnalysisSerializer)


@add_docs(
    description="This endpoint allows to start a Job related to an observable",
    request=PlaybookObservableAnalysisSerializer,
    responses={200: AnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_observables(request):
    return _multi_analysis_request_playbooks(
        request, PlaybookObservableAnalysisSerializer
    )


class PlaybookConfigAPI(viewsets.ModelViewSet):

    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "post":
            return PlaybookConfigCreateSerializer
        return PlaybookConfigSerializer

    def get_queryset(self):
        return PlaybookConfigSerializer.Meta.model.objects.all()

    def destroy(self, request, *args, **kwargs):
        self.permission_classes.append(IsAdminUser)
        return super().destroy(request, *args, **kwargs)
