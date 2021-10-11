# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
from typing import Union

from wsgiref.util import FileWrapper
from django.utils.decorators import method_decorator
from django.http import HttpResponse
from django.db.models import Q
from django.conf import settings
from rest_framework.response import Response
from rest_framework import serializers as rfs
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
    inline_serializer,
)
from drf_spectacular.types import OpenApiTypes

from intel_owl.celery import app as celery_app
from api_app import models, serializers, permissions
from .analyzers_manager import controller as analyzers_controller
from .connectors_manager import controller as connectors_controller


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

    cleaned_connectors_list = connectors_controller.filter_connectors(
        serialized_data,
        warnings,
    )

    # save the arrived data plus new params into a new job object
    job = serializer.save(
        source=source,
        analyzers_to_execute=cleaned_analyzer_list,
        connectors_to_execute=cleaned_connectors_list,
    )

    logger.info(f"New Job added to queue <- {repr(job)}.")

    # Check if task is test or not
    if not settings.TEST_MODE:
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
        "connectors_running": cleaned_connectors_list,
    }

    logger.debug(response_dict)

    return Response(
        response_dict, status=status.HTTP_200_OK
    )  # lgtm [py/stack-trace-exposure]


""" REST API endpoints """


@add_docs(
    description="""
    This is useful to avoid repeating the same analysis multiple times.
    By default this API checks if there are existing analysis related to the md5 in
    status "running" or "reported_without_fails"
    Also, you need to specify the analyzers needed because, otherwise, it is
    highly probable that you won't get all the results that you expect""",
    request=serializers.JobAvailabilitySerializer,
    responses={
        200: inline_serializer(
            name="AskAnalysisAvailabilitySuccessResponse",
            fields={
                "status": rfs.StringRelatedField(),
                "job_id": rfs.StringRelatedField(),
                "analyzers_to_execute": OpenApiTypes.OBJECT,
            },
        ),
    },
)
@api_view(["POST"])
@permission_required_or_403("api_app.view_job")
def ask_analysis_availability(request):
    data_received = request.data
    logger.info(
        f"ask_analysis_availability received request from {str(request.user)}."
        f"Data: {dict(data_received)}"
    )

    serializer = serializers.JobAvailabilitySerializer(
        data=data_received, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    serialized_data = serializer.validated_data

    analyzers, running_only, md5 = (
        serialized_data["analyzers"],
        serialized_data["running_only"],
        serialized_data["md5"],
    )

    if running_only:
        statuses_to_check = [models.Status.RUNNING]
    else:
        statuses_to_check = [
            models.Status.RUNNING,
            models.Status.REPORTED_WITHOUT_FAILS,
        ]

    if len(analyzers) == 0:
        query = (
            Q(md5=md5) & Q(status__in=statuses_to_check) & Q(analyzers_requested__len=0)
        )
    else:
        query = (
            Q(md5=md5)
            & Q(status__in=statuses_to_check)
            & Q(analyzers_to_execute__contains=analyzers)
        )

    try:
        last_job_for_md5 = models.Job.objects.filter(query).latest(
            "received_request_time"
        )
        response_dict = {
            "status": last_job_for_md5.status,
            "job_id": str(last_job_for_md5.id),
            "analyzers_to_execute": last_job_for_md5.analyzers_to_execute,
        }
    except models.Job.DoesNotExist:
        response_dict = {"status": "not_available"}

    logger.debug(response_dict)

    return Response(response_dict, status=status.HTTP_200_OK)


@add_docs(
    description="This endpoint allows to start a Job related to a file",
    request=serializers.FileAnalysisSerializer,
    responses={
        200: inline_serializer(
            "FileAnalysisResponseSerializer",
            fields={
                "status": rfs.StringRelatedField(),
                "job_id": rfs.IntegerField(),
                "warnings": OpenApiTypes.OBJECT,
                "analyzers_running": OpenApiTypes.OBJECT,
                "connectors_running": OpenApiTypes.OBJECT,
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
                "status": rfs.StringRelatedField(),
                "job_id": rfs.IntegerField(),
                "warnings": OpenApiTypes.OBJECT,
                "analyzers_running": OpenApiTypes.OBJECT,
                "connectors_running": OpenApiTypes.OBJECT,
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
    REST endpoint to fetch list of jobs or retrieve/delete a job with job ID.
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
    permission_classes = (permissions.ExtendedObjectPermissions,)
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

    @add_docs(
        description="Kill running job by closing celery tasks and marking as killed",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=True, methods=["patch"])
    @method_decorator(
        [
            permission_required_or_403("api_app.change_job"),
        ]
    )
    def kill(self, request, pk=None):
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
        # close celery tasks and mark reports as killed
        analyzers_controller.kill_ongoing_analysis(job)
        # set job status
        job.update_status("killed")

        return Response(status=status.HTTP_204_NO_CONTENT)

    @add_docs(
        description="Download a sample from a given Job ID.",
        request=None,
        responses={200: OpenApiTypes(7), 400: None},
    )
    @action(detail=True, methods=["get"])
    def download_sample(self, request, pk=None):
        """
        Download a sample from a given Job ID.

        :param url: pk (job_id)
        :returns: bytes
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
