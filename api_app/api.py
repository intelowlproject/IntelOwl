# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Union

from intel_owl.celery import app as celery_app
from api_app import models, serializers
from api_app.permissions import ExtendedObjectPermissions
from .analyzers_manager import controller as analyzers_controller

from wsgiref.util import FileWrapper

from django.utils.decorators import method_decorator
from django.http import HttpResponse
from django.db.models import Q
from rest_framework.response import Response
from rest_framework import serializers as BaseSerializer
from rest_framework import status, viewsets, mixins
from rest_framework.decorators import api_view, action
from rest_framework.permissions import DjangoObjectPermissions
from rest_framework.exceptions import (
    ValidationError,
    PermissionDenied,
)
from guardian.decorators import permission_required_or_403
from rest_framework_guardian.filters import ObjectPermissionsFilter
from drf_spectacular.utils import (
    extend_schema as add_docs,
    OpenApiParameter,
    inline_serializer,
)
from drf_spectacular.types import OpenApiTypes


logger = logging.getLogger(__name__)


def _analysis_request(
    request,
    serializer_class: Union[
        serializers.FileAnalysisSerializer, serializers.ObservableAnalysisSerializer
    ],
):
    """
    Prepare and send file/observable for analysis
    """
    warnings = []
    source = str(request.user)
    data_received = request.data
    logger.info(
        f"analyze_file received request from {source}." f"Data:{dict(data_received)}."
    )
    test = data_received.get("test", False)

    # serialize request data and validate
    serializer = serializer_class(data=data_received, context={"request": request})
    serializer.is_valid(raise_exception=True)

    serialized_data = serializer.validated_data
    runtime_configuration = serialized_data.pop("runtime_configuration", {})

    cleaned_analyzer_list = analyzers_controller.filter_analyzers(
        serialized_data,
        warnings,
    )
    if not cleaned_analyzer_list:
        raise ValidationError({"detail": "No Analyzers can be run after filtering."})

    # save the arrived data plus new params into a new job object
    job = serializer.save(source=source, analyzers_to_execute=cleaned_analyzer_list)

    logger.info(f"New Job added to queue <- {repr(job)}.")

    # Check if task is test or not
    if not test:
        # fire celery task
        celery_app.send_task(
            "start_analyzers",
            kwargs=dict(
                job_id=job.pk,
                analyzers_to_execute=cleaned_analyzer_list,
                runtime_configuration=runtime_configuration,
            ),
        )

    response_dict = {
        "status": "accepted",
        "job_id": job.pk,
        "warnings": warnings,
        "analyzers_running": cleaned_analyzer_list,
    }

    logger.debug(response_dict)

    return Response(response_dict, status=status.HTTP_200_OK)


""" REST API endpoints """


@add_docs(
    description="""
    This is useful to avoid repeating the same analysis multiple times.
    By default this API checks if there are existing analysis related to the md5 in
    status "running" or "reported_without_fails"
    Also, you need to specify the analyzers needed because, otherwise, it is
    highly probable that you won't get all the results that you expect""",
    parameters=[
        OpenApiParameter(
            name="md5",
            type=OpenApiTypes.STR,
            description="md5 of the sample or observable to look for",
        ),
        OpenApiParameter(
            name="analyzers_needed",
            type=OpenApiTypes.OBJECT,
            description="""
            Specify analyzers needed.
            It requires either this or run_all_available_analyzers""",
        ),
        OpenApiParameter(
            name="run_all_available_analyzers",
            type=OpenApiTypes.BOOL,
            description="If we are looking for an analysis executed with this flag set",
        ),
        OpenApiParameter(
            name="running_only",
            type=OpenApiTypes.BOOL,
            description="""
            Check only for running analysis,
            default False, any value is True""",
        ),
    ],
    responses={
        200: inline_serializer(
            name="AskAnalysisAvailabilitySuccessResponse",
            fields={
                "status": BaseSerializer.StringRelatedField(),
                "job_id": BaseSerializer.StringRelatedField(),
                "analyzers_to_execute": OpenApiTypes.OBJECT,
            },
        ),
        400: inline_serializer(
            name="AskAnalysisAvailabilityInsufficientDataResponse",
            fields={
                "error": BaseSerializer.StringRelatedField(),
            },
        ),
        500: inline_serializer(
            name="AskAnalysisAvailabilityErrorResponse",
            fields={
                "detail": BaseSerializer.StringRelatedField(),
            },
        ),
    },
)
@api_view(["GET"])
@permission_required_or_403("api_app.view_job")
def ask_analysis_availability(request):
    source = str(request.user)
    analyzers_needed_list = []
    run_all_available_analyzers = False
    try:
        data_received = request.query_params
        logger.info(
            f"ask_analysis_availability received request from {source}."
            f"Data: {dict(data_received)}"
        )

        if "md5" not in data_received:
            return Response({"error": "800"}, status=status.HTTP_400_BAD_REQUEST)

        if (
            "analyzers_needed" not in data_received
            and "run_all_available_analyzers" not in data_received
        ):
            return Response({"error": "801"}, status=status.HTTP_400_BAD_REQUEST)

        if (
            "run_all_available_analyzers" in data_received
            and data_received["run_all_available_analyzers"]
        ):
            run_all_available_analyzers = True
        if not run_all_available_analyzers:
            if "analyzers_needed" not in data_received:
                return Response({"error": "802"}, status=status.HTTP_400_BAD_REQUEST)
            analyzers_needed_list = data_received["analyzers_needed"].split(",")

        running_only = False
        if "running_only" in data_received:
            running_only = True

        md5 = data_received["md5"]

        if running_only:
            statuses_to_check = ["running"]
        else:
            statuses_to_check = ["running", "reported_without_fails"]

        if run_all_available_analyzers:
            query = (
                Q(md5=md5)
                & Q(status__in=statuses_to_check)
                & Q(run_all_available_analyzers=True)
            )
        else:
            query = (
                Q(md5=md5)
                & Q(status__in=statuses_to_check)
                & Q(analyzers_to_execute__contains=analyzers_needed_list)
            )

        last_job_for_md5_set = models.Job.objects.filter(query).order_by(
            "-received_request_time"
        )
        if last_job_for_md5_set:
            last_job_for_md5 = last_job_for_md5_set[0]
            response_dict = {
                "status": last_job_for_md5.status,
                "job_id": str(last_job_for_md5.id),
                "analyzers_to_execute": last_job_for_md5.analyzers_to_execute,
            }
        else:
            response_dict = {"status": "not_available"}

        logger.debug(response_dict)

        return Response(response_dict, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"ask_analysis_availability requester:{source} error:{e}.")
        return Response(
            {"detail": "error in ask_analysis_availability. Check logs."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@add_docs(
    description="This endpoint allows to start a Job related to a file",
    request=serializers.FileAnalysisSerializer,
    responses={
        200: inline_serializer(
            "FileAnalysisResponseSerializer",
            fields={
                "status": BaseSerializer.StringRelatedField(),
                "job_id": BaseSerializer.IntegerField(),
                "warnings": OpenApiTypes.OBJECT,
                "analyzers_running": OpenApiTypes.OBJECT,
            },
        ),
    },
)
@api_view(["POST"])
@permission_required_or_403("api_app.add_job")
def analyze_file(request):
    return _analysis_request(request, serializers.FileAnalysisSerializer)


@add_docs(
    description="This endpoint allows to start a Job related to an observable",
    request=serializers.ObservableAnalysisSerializer,
    responses={
        200: inline_serializer(
            "ObservableAnalysisResponseSerializer",
            fields={
                "status": BaseSerializer.StringRelatedField(),
                "job_id": BaseSerializer.IntegerField(),
                "warnings": OpenApiTypes.OBJECT,
                "analyzers_running": OpenApiTypes.OBJECT,
            },
        ),
    },
)
@api_view(["POST"])
@permission_required_or_403("api_app.add_job")
def analyze_observable(request):
    return _analysis_request(request, serializers.ObservableAnalysisSerializer)


@add_docs(
    description="""
    REST endpoint to fetch list of jobs or retrieve a job with job ID.
    Requires authentication.
    """
)
class JobViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):

    queryset = (
        models.Job.objects.prefetch_related("tags")
        .order_by("-received_request_time")
        .all()
    )
    serializer_class = serializers.JobSerializer
    serializer_action_classes = {
        "list": serializers.JobListSerializer,
    }
    permission_classes = (ExtendedObjectPermissions,)
    filter_backends = (ObjectPermissionsFilter,)

    def get_serializer_class(self, *args, **kwargs):
        """
        Instantiate the list of serializers per action from class attribute
        (must be defined).
        """
        kwargs["partial"] = True
        try:
            return self.serializer_action_classes[self.action]
        except (KeyError, AttributeError):
            return super(JobViewSet, self).get_serializer_class()

    @action(detail=True, methods=["patch"])
    @method_decorator(
        [
            permission_required_or_403("api_app.change_job"),
        ]
    )
    def kill(self, request, pk=None):
        """
        Kill running job by closing celery tasks and marking as killed

        :param url: pk (job_id)
        :returns:
         - 200 - if killed
         - 404 - not found
         - 403 - forbidden, 400 bad request
        """
        logger.info(
            f"kill running job received request from {str(request.user)} "
            f"-- (job_id:{pk})."
        )

        # get job object or raise 404
        job = self.get_object()
        if not request.user.has_perm("api_app.change_job", job):
            raise PermissionDenied()

        # check if job running
        if job.status != "running":
            raise ValidationError({"detail": "Job is not running"})

        # close celery tasks
        analyzers_controller.kill_running_analysis(pk)
        # set job status
        job.update_status("killed")

        return Response(status=status.HTTP_200_OK)

    @action(detail=True, methods=["get"])
    def download_sample(self, request, pk=None):
        """
        Download a sample from a given Job ID.
        """
        # get job object
        job = self.get_object()

        # check permission
        if not request.user.has_perm("api_app.view_job", job):
            raise PermissionDenied()

        # make sure it is a sample
        if not job.is_sample:
            raise ValidationError(
                {"detail": "Requested job does not have a sample associated with it."}
            )
        response = HttpResponse(FileWrapper(job.file), content_type=job.file_mimetype)
        response["Content-Disposition"] = f"attachment; filename={job.file_name}"
        return response


@add_docs(
    description="""
    REST endpoint to pefrom CRUD operations on Job tags.
    Requires authentication.
    POST/PUT/DELETE requires model/object level permission."""
)
class TagViewSet(viewsets.ModelViewSet):
    queryset = models.Tag.objects.all()
    serializer_class = serializers.TagSerializer
    permission_classes = (DjangoObjectPermissions,)
