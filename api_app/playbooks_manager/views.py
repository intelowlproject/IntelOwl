# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from typing import Union

from django.conf import settings
from intel_owl.celery import app as celery_app
from api_app.serializers import AnalysisResponseSerializer, FileAnalysisSerializer, ObservableAnalysisSerializer
from .serializers import PlaybookAnalysisResponseSerializer
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework.decorators import api_view

from certego_saas.ext.views import APIView

from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.response import Response

from .serializers import PlaybookConfigSerializer
from . import controller as playbooks_controller

logger = logging.getLogger(__name__)


__all__ = [
    "PlaybookListAPI",
]

def _analysis_request_playbooks(
    request,
    serializer_class:  Union[FileAnalysisSerializer, ObservableAnalysisSerializer],
):
    """
    Prepare and send file/observable for running playbooks
    """

    warnings = []
    logger.info(
        f"_analysis_request {serializer_class} received request from {request.user}."
        f"Data:{dict(request.data)}."
    )

    # serialize request data and validate
    serializer = serializer_class(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)

    serialized_data = serializer.validated_data

    cleaned_playbooks_list, analyzers_to_be_run, connectors_to_be_run = playbooks_controller.filter_playbooks(
        serialized_data,
        warnings
    )

    # save the arrived data plus new params into a new job object
    job = serializer.save(
        user=request.user,
        playbooks_to_execute=cleaned_playbooks_list,
    )


    logger.info(f"New Job added to queue <- {repr(job)}.")

    # Check if task is test or not
    if not settings.STAGE_CI:
        # fire celery task
        celery_app.send_task(
            "start_playbooks",
            kwargs=dict(
                job_id=job.pk,
                playbooks_to_execute=cleaned_playbooks_list,
            ),
        )
    ser = PlaybookAnalysisResponseSerializer(
        data={
            "status": "accepted",
            "job_id": job.pk,
            "warnings": warnings,
            "playbooks_running": cleaned_playbooks_list,
            "analyzers_running": analyzers_to_be_run,
            "connectors_running": connectors_to_be_run
        }
    )
    ser.is_valid(raise_exception=True)

    response_dict = ser.data

    logger.debug(response_dict)

    return Response(
        response_dict,
        status=status.HTTP_200_OK,
    )

@add_docs(
    description="This endpoint allows to start a Job related to a file",
    request=FileAnalysisSerializer,
    responses={200: PlaybookAnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_file(request): 
    return _analysis_request_playbooks(request, FileAnalysisSerializer)


@add_docs(
    description="This endpoint allows to start a Job related to an observable",
    request=ObservableAnalysisSerializer,
    responses={200: PlaybookAnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_observable(request):
    return _analysis_request_playbooks(request, ObservableAnalysisSerializer)


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