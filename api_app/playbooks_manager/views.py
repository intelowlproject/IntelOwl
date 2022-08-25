# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Union

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from api_app.serializers import FileAnalysisSerializer, ObservableAnalysisSerializer
from certego_saas.ext.views import APIView

from ..views import _multi_analysis_request
from .serializers import PlaybookAnalysisResponseSerializer, PlaybookConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "PlaybookListAPI",
]


def _multi_analysis_request_playbooks(
    request,
    serializer_class: Union[FileAnalysisSerializer, ObservableAnalysisSerializer],
):
    """
    Prepare and send multiple files/observables for running playbooks
    """
    response = _multi_analysis_request(
        user=request.user,
        data=request.data,
        serializer_class=serializer_class,
        playbook_scan=True,
    )["results"][0]

    return Response(
        response,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="This endpoint allows to start a Job related to a file",
    request=FileAnalysisSerializer,
    responses={200: PlaybookAnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_files(request):
    return _multi_analysis_request_playbooks(request, FileAnalysisSerializer)


@add_docs(
    description="This endpoint allows to start a Job related to an observable",
    request=ObservableAnalysisSerializer,
    responses={200: PlaybookAnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_observables(request):
    return _multi_analysis_request_playbooks(request, ObservableAnalysisSerializer)


class PlaybookListAPI(APIView):
    serializer_class = PlaybookConfigSerializer

    @add_docs(
        description="Get and parse the `playbook_config.json` file,",
        parameters=[],
        responses={
            200: PlaybookConfigSerializer,
            500: inline_serializer(
                name="GetPlaybookConfigsFailedResponse",
                fields={"error": rfs.StringRelatedField()},
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        try:
            pc = self.serializer_class.read_and_verify_config()
            return Response(pc, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(
                f"get_playbook_configs requester:{str(request.user)} error:{e}."
            )
            return Response(
                {"error": "error in get_playbook_configs. Check logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
