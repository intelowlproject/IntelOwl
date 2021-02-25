import logging

from api_app import models, serializers, helpers
from api_app.permissions import ExtendedObjectPermissions
from .script_analyzers import general

from wsgiref.util import FileWrapper

from django.http import HttpResponse
from django.db.models import Q
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework import status, viewsets, mixins
from rest_framework.decorators import api_view, action
from rest_framework.permissions import DjangoObjectPermissions
from guardian.decorators import permission_required_or_403
from rest_framework_guardian.filters import ObjectPermissionsFilter


logger = logging.getLogger(__name__)


""" REST API endpoints """


@swagger_auto_schema(
    methods=["get"],
    manual_parameters=[
        openapi.Parameter(
            "md5",
            openapi.IN_QUERY,
            "md5 of the sample or observable to look for",
            type=openapi.TYPE_STRING,
        ),
        openapi.Parameter(
            "analyzers_needed",
            openapi.IN_QUERY,
            "specify analyzers needed. It requires either this or "
            "run_all_available_analyzers",
            type=openapi.TYPE_ARRAY,
            items=openapi.Items(type=openapi.TYPE_STRING),
        ),
        openapi.Parameter(
            "run_all_available_analyzers",
            openapi.IN_QUERY,
            "if we are looking for an analysis executed with this flag set",
            type=openapi.TYPE_BOOLEAN,
        ),
        openapi.Parameter(
            "running_only",
            openapi.IN_QUERY,
            "check only for running analysis, default False, any value is True",
            type=openapi.TYPE_BOOLEAN,
        ),
    ],
    responses={
        200: openapi.Response("if ok with list of all analysis related to that md5"),
        500: openapi.Response("if failed"),
    },
)
@api_view(["GET"])
@permission_required_or_403("api_app.view_job")
def ask_analysis_availability(request):
    """
    This is useful to avoid repeating the same analysis multiple times.
    By default this API checks if there are existing analysis related to the md5 in
    status "running" or "reported_without_fails"
    Also, you need to specify the analyzers needed because, otherwise, it is
    highly probable that you won't get all the results that you expect
    """
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


@swagger_auto_schema(
    methods=["post"],
    manual_parameters=[
        openapi.Parameter(
            "is_sample",
            openapi.IN_QUERY,
            "is a sample (file) or an observable (domain, ip, ...)",
            type=openapi.TYPE_BOOLEAN,
        ),
        openapi.Parameter(
            "md5",
            openapi.IN_QUERY,
            "md5 of the item to analyze",
            type=openapi.TYPE_STRING,
        ),
        openapi.Parameter(
            "file",
            openapi.IN_QUERY,
            "required if is_sample=True, the binary",
            type=openapi.FORMAT_BINARY,
        ),
        openapi.Parameter(
            "file_mimetype",
            openapi.IN_QUERY,
            "optional, the binary mimetype, calculated by default",
            type=openapi.TYPE_STRING,
        ),
        openapi.Parameter(
            "file_name",
            openapi.IN_QUERY,
            "optional if is_sample=True, the binary name",
            type=openapi.TYPE_STRING,
        ),
        openapi.Parameter(
            "observable_name",
            openapi.IN_QUERY,
            "required if is_sample=False, the observable value",
            type=openapi.TYPE_STRING,
        ),
        openapi.Parameter(
            "observable_classification",
            openapi.IN_QUERY,
            "required if is_sample=False, (domain, ip, ...)",
            type=openapi.TYPE_STRING,
        ),
        openapi.Parameter(
            "analyzers_requested",
            openapi.IN_QUERY,
            "list of requested analyzer to run, before filters",
            type=openapi.TYPE_ARRAY,
            items=openapi.Items(type=openapi.TYPE_STRING),
        ),
        openapi.Parameter(
            "tags_id",
            openapi.IN_QUERY,
            "list of id's of tags to apply to job",
            type=openapi.TYPE_ARRAY,
            items=openapi.Items(type=openapi.TYPE_INTEGER),
        ),
        openapi.Parameter(
            "run_all_available_analyzers",
            openapi.IN_QUERY,
            type=openapi.TYPE_BOOLEAN,
            default=False,
        ),
        openapi.Parameter(
            "private",
            openapi.IN_QUERY,
            "enable it to allow view permissions to only requesting user's groups.",
            type=openapi.TYPE_BOOLEAN,
            default=False,
        ),
        openapi.Parameter(
            "force_privacy",
            openapi.IN_QUERY,
            "enable it if you want to avoid to run analyzers with privacy issues",
            type=openapi.TYPE_BOOLEAN,
            default=False,
        ),
        openapi.Parameter(
            "disable_external_analyzers",
            openapi.IN_QUERY,
            "enable it if you want to exclude external analyzers",
            type=openapi.TYPE_BOOLEAN,
            default=False,
        ),
        openapi.Parameter(
            "runtime_configuration",
            openapi.IN_QUERY,
            "contains additional parameters for particular analyzers",
            type=openapi.TYPE_OBJECT,
        ),
        openapi.Parameter(
            "test",
            openapi.IN_QUERY,
            "disable analysis for API testing",
            type=openapi.TYPE_BOOLEAN,
        ),
    ],
    responses={
        202: openapi.Response("if accepted"),
        500: openapi.Response("if failed"),
    },
)
@api_view(["POST"])
@permission_required_or_403("api_app.add_job")
def send_analysis_request(request):
    """
    This endpoint allows to start a Job related to a file or an observable
    """
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
            analyzers_config = helpers.get_analyzer_config()
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


@swagger_auto_schema(
    methods=["get"],
    manual_parameters=[
        openapi.Parameter(
            "job_id",
            openapi.IN_QUERY,
            "Job ID",
            type=openapi.FORMAT_UUID,
        ),
    ],
    responses={
        200: openapi.Response("if ok"),
        500: openapi.Response("if failed"),
    },
)
@api_view(["GET"])
@permission_required_or_403("api_app.view_job")
def ask_analysis_result(request):
    """
    Endpoint to retrieve the status and results of a specific Job based on its ID
    """
    source = str(request.user)
    try:
        data_received = request.query_params
        logger.info(
            f"""
            ask_analysis_result received request from {source}.
             Data:{dict(data_received)}
            """
        )
        if "job_id" not in data_received:
            return Response({"error": "820"}, status=status.HTTP_400_BAD_REQUEST)

        job_id = data_received["job_id"]
        try:
            job = models.Job.objects.get(id=job_id)
            # check permission
            if not request.user.has_perm("api_app.view_job", job):
                return Response(
                    {"detail": "You don't have permission to perform this operation."},
                    status=status.HTTP_403_FORBIDDEN,
                )
        except models.Job.DoesNotExist:
            response_dict = {"status": "not_available"}
        else:
            response_dict = {
                "status": job.status,
                "results": job.analysis_reports,
                "job_id": str(job.id),
            }
            # adding elapsed time
            finished_analysis_time = getattr(job, "finished_analysis_time", None)
            if not finished_analysis_time:
                finished_analysis_time = helpers.get_now()
            elapsed_time = finished_analysis_time - job.received_request_time
            seconds = elapsed_time.total_seconds()
            response_dict["elapsed_time_in_seconds"] = seconds

        logger.debug(response_dict)

        return Response(response_dict, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"ask_analysis_result requester:{source} error:{e}")
        return Response(
            {"error": "error in ask_analysis_result. Check logs"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@swagger_auto_schema(
    methods=["get"],
    responses={
        200: openapi.Response("if ok"),
        500: openapi.Response("if failed"),
    },
)
@api_view(["GET"])
def get_analyzer_configs(request):
    """
    get the uploaded analyzer configuration,
    can be useful if you want to choose the analyzers programmatically
    """
    try:
        logger.info(f"get_analyzer_configs received request from {str(request.user)}.")

        analyzers_config = helpers.get_analyzer_config()

        return Response(analyzers_config)

    except Exception as e:
        logger.exception(
            f"get_analyzer_configs requester:{str(request.user)} error:{e}."
        )
        return Response(
            {"error": "error in get_analyzer_configs. Check logs."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@swagger_auto_schema(
    methods=["get"],
    manual_parameters=[
        openapi.Parameter(
            "job_id",
            openapi.IN_QUERY,
            "Job ID",
            type=openapi.FORMAT_UUID,
        ),
    ],
    responses={
        200: openapi.Response("if found"),
        403: openapi.Response("forbidden"),
        404: openapi.Response("not found"),
    },
)
@api_view(["GET"])
def download_sample(request):
    """
    this method is used to download a sample from a Job ID
    """
    try:
        data_received = request.query_params
        logger.info(f"Get binary by Job ID. Data received {data_received}")
        if "job_id" not in data_received:
            return Response({"error": "821"}, status=status.HTTP_400_BAD_REQUEST)
        # get job object
        try:
            job = models.Job.objects.get(id=data_received["job_id"])
        except models.Job.DoesNotExist:
            return Response({"detail": "not found"}, status=status.HTTP_404_NOT_FOUND)
        # check permission
        if not request.user.has_perm("api_app.view_job", job):
            return Response(
                {"detail": "You don't have permission to perform this operation."},
                status=status.HTTP_403_FORBIDDEN,
            )
        # make sure it is a sample
        if not job.is_sample:
            return Response(
                {"detail": "job without sample"}, status=status.HTTP_400_BAD_REQUEST
            )
        response = HttpResponse(FileWrapper(job.file), content_type=job.file_mimetype)
        response["Content-Disposition"] = f"attachment; filename={job.file_name}"
        return response

    except Exception as e:
        logger.exception(f"download_sample requester:{str(request.user)} error:{e}.")
        return Response(
            {"detail": "error in download_sample. Check logs."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class JobViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """
    REST endpoint to fetch list of jobs or retrieve a job with job ID.
    Requires authentication.
    """

    queryset = models.Job.objects.order_by("-received_request_time").all()
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

    @swagger_auto_schema(
        methods=["patch"],
        manual_parameters=[
            openapi.Parameter(
                "job_id",
                openapi.IN_QUERY,
                "Job ID",
                type=openapi.FORMAT_UUID,
            ),
        ],
        responses={
            200: openapi.Response("if killed"),
            400: openapi.Response("bad request"),
            403: openapi.Response("forbidden"),
            404: openapi.Response("not found"),
        },
    )
    @action(detail=True, methods=["patch"])
    def kill(self, request, pk=None):
        """
        kill running job by closing celery tasks and marking as killed
        """
        try:
            job_id = pk
            logger.info(
                f"kill running job received request from {str(request.user)} "
                f"for JOB ID {job_id}."
            )
            # get job
            try:
                job = models.Job.objects.get(pk=pk)
            except models.Job.DoesNotExist:
                return Response(
                    {"detail": "job not found"}, status=status.HTTP_404_NOT_FOUND
                )
            # check permission
            if not request.user.has_perm("api_app.change_job", job):
                return Response(
                    {"detail": "You don't have permission to perform this operation."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            # check if job running
            if job.status != "running":
                return Response(
                    {"detail": "job not running"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # close celery tasks
            general.kill_running_analysis(job_id)
            # set job status
            job.status = "killed"
            job.save()
            return Response(status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception(
                f"kill_running_job requester:{str(request.user)} error:{e}."
            )
            return Response(
                {"error": "error in kill_running_job. Check logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class TagViewSet(viewsets.ModelViewSet):
    """
    REST endpoint to pefrom CRUD operations on Job tags.
    Requires authentication.
    POST/PUT/DELETE requires model/object level permission.
    """

    queryset = models.Tag.objects.all()
    serializer_class = serializers.TagSerializer
    permission_classes = (DjangoObjectPermissions,)
