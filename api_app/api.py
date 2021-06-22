# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app import models, serializers, helpers
from api_app.permissions import ExtendedObjectPermissions
from .analyzers_manager import general
from .analyzers_manager.helpers import get_verified_analyzer_config

from wsgiref.util import FileWrapper

from django.utils.decorators import method_decorator
from django.http import HttpResponse
from django.db.models import Q
from rest_framework.response import Response
from rest_framework import serializers as BaseSerializer
from rest_framework import status, viewsets, mixins
from rest_framework.decorators import api_view, action
from rest_framework.permissions import DjangoObjectPermissions
from rest_framework.exceptions import NotFound, ParseError, PermissionDenied
from guardian.decorators import permission_required_or_403
from rest_framework_guardian.filters import ObjectPermissionsFilter
from drf_spectacular.utils import (
    extend_schema as add_docs,
    OpenApiParameter,
    inline_serializer,
)
from drf_spectacular.types import OpenApiTypes


logger = logging.getLogger(__name__)


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
    description="""
    This endpoint allows to start a Job related to a file or an observable""",
    parameters=[
        OpenApiParameter(
            name="is_sample",
            type=OpenApiTypes.BOOL,
            description="is a sample (file) or an observable (domain, ip, ...)",
        ),
        OpenApiParameter(
            name="md5", type=OpenApiTypes.STR, description="md5 of the item to analyze"
        ),
        OpenApiParameter(
            name="file",
            type=OpenApiTypes.BINARY,
            description="required if is_sample=True, the binary",
        ),
        OpenApiParameter(
            name="file_mimetype",
            type=OpenApiTypes.STR,
            description="optional, the binary mimetype, calculated by default",
        ),
        OpenApiParameter(
            name="file_name",
            type=OpenApiTypes.STR,
            description="optional if is_sample=True, the binary name",
        ),
        OpenApiParameter(
            name="observable_name",
            type=OpenApiTypes.STR,
            description="required if is_sample=False, the observable value",
        ),
        OpenApiParameter(
            name="observable_classification",
            type=OpenApiTypes.STR,
            description="required if is_sample=False, (domain, ip, ...)",
        ),
        OpenApiParameter(
            name="analyzers_requested",
            type=OpenApiTypes.OBJECT,
            description="list of requested analyzer to run, before filters",
        ),
        OpenApiParameter(
            name="tags_id",
            type=OpenApiTypes.OBJECT,
            description="list of id's of tags to apply to job",
        ),
        OpenApiParameter(
            name="run_all_available_analyzers",
            type=OpenApiTypes.BOOL,
            description="default False",
        ),
        OpenApiParameter(
            name="private",
            type=OpenApiTypes.BOOL,
            description="""
            Default False,
            enable it to allow view permissions to only requesting user's groups.""",
        ),
        OpenApiParameter(
            name="force_privacy",
            type=OpenApiTypes.BOOL,
            description="""
            Default False,
            enable it if you want to avoid to run analyzers with privacy issues""",
        ),
        OpenApiParameter(
            name="disable_external_analyzers",
            type=OpenApiTypes.BOOL,
            description="""
            Default False, enable it if you want to exclude external analyzers""",
        ),
        OpenApiParameter(
            name="runtime_configuration",
            type=OpenApiTypes.OBJECT,
            description=r"""
            Default {}, contains additional parameters for particular analyzers""",
        ),
        OpenApiParameter(
            name="test",
            type=OpenApiTypes.BOOL,
            description="disable analysis for API testing",
        ),
    ],
    responses={
        202: inline_serializer(
            "SendAnalysisRequestSuccessResponse",
            fields={
                "status": BaseSerializer.StringRelatedField(),
                "job_id": BaseSerializer.IntegerField(),
                "warnings": OpenApiTypes.OBJECT,
                "analyzers_running": OpenApiTypes.OBJECT,
            },
        ),
        400: inline_serializer(
            name="SendAnalysisRequestInsufficientData",
            fields={
                "error": BaseSerializer.StringRelatedField(),
            },
        ),
        500: inline_serializer(
            name="SendAnalysisRequestError",
            fields={
                "detail": BaseSerializer.StringRelatedField(),
            },
        ),
    },
)
@api_view(["POST"])
@permission_required_or_403("api_app.add_job")
def send_analysis_request(request):
    source = str(request.user)
    warnings = []
    try:
        data_received = request.data
        logger.info(
            f"send_analysis_request received request from {source}."
            f"Data:{dict(data_received)}."
        )

        test = data_received.get("test", False)

        params = {"source": source}

        serializer = serializers.JobSerializer(
            data=data_received, context={"request": request}
        )
        if serializer.is_valid():
            serialized_data = serializer.validated_data
            logger.info(f"serialized_data: {serialized_data}")

            # some values are mandatory only in certain cases
            if serialized_data["is_sample"]:
                if "file" not in data_received:
                    return Response(
                        {"error": "810"}, status=status.HTTP_400_BAD_REQUEST
                    )
                if "file_mimetype" not in data_received:
                    serialized_data["file_mimetype"] = helpers.calculate_mimetype(
                        data_received["file"], data_received.get("file_name", "")
                    )
            else:
                if "observable_name" not in data_received:
                    return Response(
                        {"error": "812"}, status=status.HTTP_400_BAD_REQUEST
                    )
                if "observable_classification" not in data_received:
                    return Response(
                        {"error": "813"}, status=status.HTTP_400_BAD_REQUEST
                    )

            # we need to clean the list of requested analyzers,
            # ... based on configuration data
            analyzers_config = get_verified_analyzer_config()
            run_all_available_analyzers = serialized_data.get(
                "run_all_available_analyzers", False
            )
            analyzers_requested = serialized_data.get("analyzers_requested", [])
            if run_all_available_analyzers:
                if analyzers_requested:
                    logger.info(
                        """either you specify a list of requested analyzers or the
                         'run_all_available_analyzers' parameter, not both"""
                    )
                    return Response(
                        {"error": "816"}, status=status.HTTP_400_BAD_REQUEST
                    )
                # just pick all available analyzers
                analyzers_requested = [
                    analyzer_name for analyzer_name in analyzers_config
                ]
            cleaned_analyzer_list = helpers.filter_analyzers(
                serialized_data,
                analyzers_requested,
                analyzers_config,
                warnings,
                run_all=run_all_available_analyzers,
            )
            params["analyzers_to_execute"] = cleaned_analyzer_list
            if len(cleaned_analyzer_list) < 1:
                logger.info(
                    """after the filter, no analyzers can be run.
                     Try with other analyzers"""
                )
                return Response({"error": "814"}, status=status.HTTP_400_BAD_REQUEST)

            # save the arrived data plus new params into a new job object
            serializer.save(**params)
            job_id = serializer.data.get("id", None)
            md5 = serializer.data.get("md5", "")
            logger.info(f"New Job added with ID: #{job_id} and md5: {md5}.")
            if not job_id:
                return Response({"error": "815"}, status=status.HTTP_400_BAD_REQUEST)

        else:
            error_message = f"serializer validation failed: {serializer.errors}"
            logger.error(error_message)
            return Response(
                {"error": error_message}, status=status.HTTP_400_BAD_REQUEST
            )

        is_sample = serializer.data.get("is_sample", False)
        if not test:
            general.start_analyzers(
                params["analyzers_to_execute"],
                analyzers_config,
                serialized_data["runtime_configuration"],
                job_id,
                md5,
                is_sample,
            )

        response_dict = {
            "status": "accepted",
            "job_id": job_id,
            "warnings": warnings,
            "analyzers_running": cleaned_analyzer_list,
        }

        logger.debug(response_dict)

        return Response(response_dict, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"receive_analysis_request requester:{source} error:{e}.")
        return Response(
            {"detail": "error in send_analysis_request. Check logs"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@add_docs(
    description="""
Get the uploaded analyzer configuration,
can be useful if you want to choose the analyzers programmatically""",
    parameters=[],
    responses={
        200: inline_serializer(
            name="GetAnalyzerConfigsSuccessResponse",
            fields={"analyzers_config": BaseSerializer.DictField()},
        ),
        500: inline_serializer(
            name="GetAnalyzerConfigsFailedResponse",
            fields={"error": BaseSerializer.StringRelatedField()},
        ),
    },
)
@api_view(["GET"])
def get_analyzer_configs(request):
    try:
        logger.info(f"get_analyzer_configs received request from {str(request.user)}.")
        ac = get_verified_analyzer_config()
        return Response(ac, status=status.HTTP_200_OK)
    except Exception as e:
        logger.exception(
            f"get_analyzer_configs requester:{str(request.user)} error:{e}."
        )
        return Response(
            {"error": "error in get_analyzer_configs. Check logs."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@add_docs(
    description="This method is used to download a sample from a Job ID",
    parameters=[
        OpenApiParameter(name="job_id", type=OpenApiTypes.INT, description="Job Id")
    ],
    responses={
        200: OpenApiTypes.BINARY,
        400: inline_serializer(
            "DownloadSampleInsufficientData",
            fields={"detail": BaseSerializer.StringRelatedField()},
        ),
        500: inline_serializer(
            "DownloadSampleInsufficientData",
            fields={"detail": BaseSerializer.StringRelatedField()},
        ),
    },
)
@api_view(["GET"])
def download_sample(request):
    data_received = request.query_params
    logger.info(f"Get binary by Job ID. Data received {data_received}")
    if "job_id" not in data_received:
        return Response({"error": "821"}, status=status.HTTP_400_BAD_REQUEST)
    # get job object or raise 404
    try:
        job = models.Job.objects.get(pk=data_received["job_id"])
    except models.Job.DoesNotExist:
        raise NotFound()
    # check permission
    if not request.user.has_perm("api_app.view_job", job):
        raise PermissionDenied()
    # make sure it is a sample
    if not job.is_sample:
        raise ParseError(
            detail="Requested job does not have a sample associated with it."
        )
    response = HttpResponse(FileWrapper(job.file), content_type=job.file_mimetype)
    response["Content-Disposition"] = f"attachment; filename={job.file_name}"
    return response


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
        try:
            job = models.Job.objects.get(pk=pk)
        except models.Job.DoesNotExist:
            raise NotFound()
        # check permission
        if not request.user.has_perm("api_app.change_job", job):
            raise PermissionDenied()
        # check if job running
        if job.status != "running":
            raise ParseError(detail="Job is not running")
        # close celery tasks
        general.kill_running_analysis(pk)
        # set job status
        job.status = "killed"
        job.save()
        return Response(status=status.HTTP_200_OK)


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
