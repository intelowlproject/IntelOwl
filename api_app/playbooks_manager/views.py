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

from api_app.playbooks_manager.serializers import (
    CachedPlaybooksSerializer,
    PlaybookConfigSerializer,
)
from api_app.serializers import (
    PlaybookAnalysisResponseSerializer,
    PlaybookFileAnalysisSerializer,
    PlaybookObservableAnalysisSerializer,
)
from certego_saas.ext.views import APIView

from ..views import _multi_analysis_request

logger = logging.getLogger(__name__)


__all__ = [
    "PlaybookListAPI",
]


def _cache_playbook(data, serializer_class: CachedPlaybooksSerializer):
    """
    Cache playbook after a scan
    """

    serializer = serializer_class(data=data)
    serializer.is_valid(raise_exception=True)

    serializer.save()

    return serializer.data


@api_view(["POST"])
def cache_playbook_view(
    request,
):
    logger.info(f"received request from {request.user}." f"Data: {request.data}.")

    response = _cache_playbook(
        data=request.data,
        serializer_class=CachedPlaybooksSerializer,
    )

    return Response(
        response,
        status=status.HTTP_200_OK,
    )


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
        user=request.user,
        data=request.data,
        serializer_class=serializer_class,
        playbook_scan=True,
    )

    return Response(
        response,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="This endpoint allows to start a Job related to a file",
    request=PlaybookFileAnalysisSerializer,
    responses={200: PlaybookAnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_files(request):
    return _multi_analysis_request_playbooks(request, PlaybookFileAnalysisSerializer)


@add_docs(
    description="This endpoint allows to start a Job related to an observable",
    request=PlaybookObservableAnalysisSerializer,
    responses={200: PlaybookAnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_observables(request):
    return _multi_analysis_request_playbooks(
        request, PlaybookObservableAnalysisSerializer
    )


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
            pc = self.serializer_class.output_with_cached_playbooks()
            return Response(pc, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(
                f"get_playbook_configs requester:{str(request.user)} error:{e}."
            )
            return Response(
                {"error": "error in get_playbook_configs. Check logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
