# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import datetime
import logging
import uuid
from abc import ABCMeta, abstractmethod

from django.db.models import Count, Q
from django.db.models.functions import Trunc
from django.http import FileResponse
from django.utils.timezone import now
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from api_app.websocket import JobConsumer
from certego_saas.apps.organization.permissions import (
    IsObjectOwnerOrSameOrgPermission as IsObjectUserOrSameOrgPermission,
)
from certego_saas.apps.organization.permissions import (
    IsObjectOwnerPermission as IsObjectUserPermission,
)
from certego_saas.ext.helpers import cache_action_response, parse_humanized_range
from certego_saas.ext.mixins import SerializerActionMixin
from certego_saas.ext.viewsets import ReadAndDeleteOnlyViewSet
from intel_owl import tasks
from intel_owl.celery import app as celery_app

from .analyzers_manager.constants import ObservableTypes
from .choices import ObservableClassification
from .decorators import deprecated_endpoint
from .filters import JobFilter
from .mixins import PaginationMixin
from .models import (
    AbstractConfig,
    AbstractReport,
    Comment,
    Job,
    OrganizationPluginConfiguration,
    PluginConfig,
    PythonConfig,
    Tag,
)
from .permissions import IsObjectAdminPermission, IsObjectOwnerPermission
from .pivots_manager.models import PivotConfig
from .serializers.job import (
    CommentSerializer,
    FileJobSerializer,
    JobAvailabilitySerializer,
    JobListSerializer,
    JobRecentScanSerializer,
    JobResponseSerializer,
    ObservableAnalysisSerializer,
    RestJobSerializer,
    TagSerializer,
)
from .serializers.plugin import PluginConfigSerializer, PythonConfigSerializer

logger = logging.getLogger(__name__)


# REST API endpoints


@add_docs(
    description="""
    This is useful to avoid repeating the same analysis multiple times.
    By default this API checks if there are existing analysis related to the md5 in
    status "running" or "reported_without_fails"
    Also, you need to specify the analyzers needed because, otherwise, it is
    highly probable that you won't get all the results that you expect""",
    request=JobAvailabilitySerializer,
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
@deprecated_endpoint(deprecation_date="01-07-2023")
@api_view(["POST"])
def ask_analysis_availability(request):
    """
    API endpoint to check for existing analysis based on an MD5 hash.

    This endpoint helps avoid redundant analysis by checking if there is already an analysis
    in progress or completed with status "running" or "reported_without_fails" for the provided MD5 hash.
    The analyzers that need to be executed should be specified to ensure expected results.

    Deprecated: This endpoint will be deprecated after 01-07-2023.

    Parameters:
    - request (POST): Contains the MD5 hash and analyzer details.

    Returns:
    - 200: JSON response with the analysis status, job ID, and analyzers to be executed.
    """
    serializer = JobAvailabilitySerializer(
        data=request.data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    try:
        job = serializer.save()
    except Job.DoesNotExist:
        result = None
    else:
        result = job
    return Response(
        JobResponseSerializer(result).data,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="""
    This is useful to avoid repeating the same analysis multiple times.
    By default this API checks if there are existing analysis related to the md5 in
    status "running" or "reported_without_fails"
    Also, you need to specify the analyzers needed because, otherwise, it is
    highly probable that you won't get all the results that you expect.
    NOTE: This API is similar to ask_analysis_availability, but it allows multiple
    md5s to be checked at the same time.""",
    responses={200: JobAvailabilitySerializer(many=True)},
)
@api_view(["POST"])
def ask_multi_analysis_availability(request):
    """
    API endpoint to check for existing analysis for multiple MD5 hashes.

    Similar to `ask_analysis_availability`, this endpoint checks for existing analysis for multiple MD5 hashes.
    It prevents redundant analysis by verifying if there are any jobs in progress or completed with status
    "running" or "reported_without_fails". The analyzers required should be specified to ensure accurate results.

    Parameters:
    - request (POST): Contains multiple MD5 hashes and analyzer details.

    Returns:
    - 200: JSON response with the analysis status, job IDs, and analyzers to be executed for each MD5 hash.
    """
    logger.info(f"received ask_multi_analysis_availability from user {request.user}")
    serializer = JobAvailabilitySerializer(
        data=request.data, context={"request": request}, many=True
    )
    serializer.is_valid(raise_exception=True)
    try:
        jobs = serializer.save()
    except Job.DoesNotExist:
        result = []
    else:
        result = jobs
    jrs = JobResponseSerializer(result, many=True).data
    logger.info(f"finished ask_multi_analysis_availability from user {request.user}")
    return Response(
        jrs,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="This endpoint allows to start a Job related for a single File."
    " Retained for retro-compatibility",
    request=FileJobSerializer,
    responses={200: JobResponseSerializer(many=True)},
)
@api_view(["POST"])
def analyze_file(request):
    """
    API endpoint to start an analysis job for a single file.

    This endpoint initiates an analysis job for a single file and sends it to the
    specified analyzers. The file-related information and analyzers should be provided
    in the request data.

    Parameters:
    - request (POST): Contains file data and analyzer details.

    Returns:
    - 200: JSON response with the job details after initiating the analysis.
    """
    logger.info(f"received analyze_file from user {request.user}")
    fas = FileJobSerializer(data=request.data, context={"request": request})
    fas.is_valid(raise_exception=True)
    job = fas.save(send_task=True)
    jrs = JobResponseSerializer(job).data
    logger.info(f"finished analyze_file from user {request.user}")
    return Response(
        jrs,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="This endpoint allows to start Jobs related to multiple Files",
    # It should be better to link the doc to the related MultipleFileAnalysisSerializer.
    # It is not straightforward because you can't just add a class
    # which extends a ListSerializer.
    # Follow this doc to try to find a fix:
    # https://drf-spectacular.readthedocs.io/en/latest/customization.html#declare-serializer-magic-with
    # -openapiserializerextension
    request=inline_serializer(
        name="MultipleFilesSerializer",
        fields={
            "files": rfs.ListField(child=rfs.FileField()),
            "file_names": rfs.ListField(child=rfs.CharField()),
            "file_mimetypes": rfs.ListField(child=rfs.CharField()),
        },
    ),
    responses={200: JobResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_files(request):
    """
    API endpoint to start analysis jobs for multiple files.

    This endpoint initiates analysis jobs for multiple files and sends them to the specified analyzers.
    The file-related information and analyzers should be provided in the request data.

    Parameters:
    - request (POST): Contains multiple file data and analyzer details.

    Returns:
    - 200: JSON response with the job details for each initiated analysis.
    """
    logger.info(f"received analyze_multiple_files from user {request.user}")
    fas = FileJobSerializer(data=request.data, context={"request": request}, many=True)
    fas.is_valid(raise_exception=True)
    parent_job = fas.validated_data[0].get("parent_job", None)
    jobs = fas.save(send_task=True, parent=parent_job)
    jrs = JobResponseSerializer(jobs, many=True).data
    logger.info(f"finished analyze_multiple_files from user {request.user}")
    return Response(
        jrs,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="This endpoint allows to start a Job related to an observable. "
    "Retained for retro-compatibility",
    request=ObservableAnalysisSerializer,
    responses={200: JobResponseSerializer},
)
@api_view(["POST"])
def analyze_observable(request):
    """
    API endpoint to start an analysis job for a single observable.

    This endpoint initiates an analysis job for a single observable (e.g., domain, IP, URL, etc.)
    and sends it to the specified analyzers. The observable-related information and analyzers should be
    provided in the request data.

    Parameters:
    - request (POST): Contains observable data and analyzer details.

    Returns:
    - 200: JSON response with the job details after initiating the analysis.
    """
    logger.info(f"received analyze_observable from user {request.user}")
    oas = ObservableAnalysisSerializer(data=request.data, context={"request": request})
    oas.is_valid(raise_exception=True)
    job = oas.save(send_task=True)
    jrs = JobResponseSerializer(job).data
    logger.info(f"finished analyze_observable from user {request.user}")
    return Response(
        jrs,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="""This endpoint allows to start Jobs related to multiple observables.
                 Observable parameter must be composed like this:
                 [(<observable_classification>, <observable_name>), ...]""",
    request=inline_serializer(
        name="MultipleObservableSerializer",
        fields={
            "observables": rfs.ListField(
                child=rfs.ListField(max_length=2, min_length=2)
            )
        },
    ),
    responses={200: JobResponseSerializer},
)
@api_view(["POST"])
def analyze_multiple_observables(request):
    """
    API endpoint to start analysis jobs for multiple observables.

    This endpoint initiates analysis jobs for multiple observables (e.g., domain, IP, URL, etc.)
    and sends them to the specified analyzers. The observables and analyzer details should
    be provided in the request data.

    Parameters:
    - request (POST): Contains multiple observable data and analyzer details.

    Returns:
    - 200: JSON response with the job details for each initiated analysis.
    """
    logger.info(f"received analyze_multiple_observables from user {request.user}")
    oas = ObservableAnalysisSerializer(
        data=request.data, many=True, context={"request": request}
    )
    oas.is_valid(raise_exception=True)
    parent_job = oas.validated_data[0].get("parent_job", None)
    jobs = oas.save(send_task=True, parent=parent_job)
    jrs = JobResponseSerializer(jobs, many=True).data
    logger.info(f"finished analyze_multiple_observables from user {request.user}")
    return Response(
        jrs,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="""
    REST endpoint to fetch list of job comments or
    retrieve/delete a job comment with job comment ID.
    Requires authentication.
    """
)
class CommentViewSet(ModelViewSet):
    """
    CommentViewSet provides the following actions:

    - **list**: Retrieve a list of comments associated with jobs visible to the authenticated user.
    - **retrieve**: Retrieve a specific comment by ID, accessible to the comment's owner or anyone in the same organization.
    - **destroy**: Delete a comment by ID, allowed only for the comment's owner.
    - **update**: Update a comment by ID, allowed only for the comment's owner.
    - **partial_update**: Partially update a comment by ID, allowed only for the comment's owner.

    Permissions:
    - **IsAuthenticated**: Requires authentication for all actions.
    - **IsObjectUserPermission**: Allows only the comment owner to update or delete the comment.
    - **IsObjectUserOrSameOrgPermission**: Allows the comment owner or anyone in the same organization to retrieve the comment.

    Queryset:
    - Filters comments to include only those associated with jobs visible to the authenticated user.
    """

    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        """
        Customizes permissions based on the action being performed.

        - For `destroy`, `update`, and `partial_update` actions, adds `IsObjectUserPermission` to ensure that only
          the comment owner can perform these actions.
        - For the `retrieve` action, adds `IsObjectUserOrSameOrgPermission` to allow the comment owner or anyone in the same
          organization to retrieve the comment.

        Returns:
        - List of applicable permissions.
        """
        permissions = super().get_permissions()

        # only the owner of the comment can update or delete the comment
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(IsObjectUserPermission())
        # the owner and anyone in the org can read the comment
        if self.action in ["retrieve"]:
            permissions.append(IsObjectUserOrSameOrgPermission())

        return permissions

    def get_queryset(self):
        """
        Filters the queryset to include only comments related to jobs visible to the authenticated user.

        - Fetches job IDs that are visible to the user.
        - Filters the comment queryset to include only comments associated with these jobs.

        Returns:
        - Filtered queryset of comments.
        """
        queryset = super().get_queryset()
        jobs = Job.objects.visible_for_user(self.request.user).values_list(
            "pk", flat=True
        )
        return queryset.filter(job__id__in=jobs)


@add_docs(
    description="""
    REST endpoint to fetch list of jobs or retrieve/delete a job with job ID.
    Requires authentication.
    """
)
class JobViewSet(ReadAndDeleteOnlyViewSet, SerializerActionMixin):
    """
    JobViewSet provides the following actions:

    - **list**: Retrieve a list of jobs visible to the authenticated user, ordered by request time.
    - **retrieve**: Retrieve a specific job by ID.
    - **destroy**: Delete a job by ID, allowed only for the job owner or anyone in the same organization.
    - **recent_scans**: Retrieve recent jobs based on an MD5 hash, limited by a maximum temporal distance.
    - **recent_scans_user**: Retrieve recent jobs for the authenticated user, filtered by sample status.
    - **retry**: Retry a job if its status is in a final state.
    - **kill**: Kill a running job by closing celery tasks and marking it as killed.
    - **download_sample**: Download a file/sample associated with a job.
    - **pivot**: Perform a pivot operation from a job's reports.
    - **aggregate_status**: Aggregate jobs by their status over a specified time range.
    - **aggregate_type**: Aggregate jobs by type (file or observable) over a specified time range.
    - **aggregate_observable_classification**: Aggregate jobs by observable classification over a specified time range.
    - **aggregate_file_mimetype**: Aggregate jobs by file MIME type over a specified time range.
    - **aggregate_observable_name**: Aggregate jobs by observable name over a specified time range.
    - **aggregate_md5**: Aggregate jobs by MD5 hash over a specified time range.

    Permissions:
    - **IsAuthenticated**: Requires authentication for all actions.
    - **IsObjectUserOrSameOrgPermission**: Allows job deletion or killing only by the job owner or anyone in the same organization.

    Queryset:
    - Prefetches related tags and orders jobs by request time, filtered to include only jobs visible to the authenticated user.
    """

    queryset = (
        Job.objects.prefetch_related("tags").order_by("-received_request_time").all()
    )
    serializer_class = RestJobSerializer
    serializer_action_classes = {
        "retrieve": RestJobSerializer,
        "list": JobListSerializer,
    }
    filterset_class = JobFilter
    ordering_fields = [
        "received_request_time",
        "finished_analysis_time",
        "process_time",
    ]

    def get_permissions(self):
        """
        Customizes permissions based on the action being performed.

        - For `destroy` and `kill` actions, adds `IsObjectUserOrSameOrgPermission` to ensure that only
          the job owner or anyone in the same organization can perform these actions.

        Returns:
        - List of applicable permissions.
        """
        permissions = super().get_permissions()
        if self.action in ["destroy", "kill"]:
            permissions.append(IsObjectUserOrSameOrgPermission())
        return permissions

    def get_queryset(self):
        """
        Filters the queryset to include only jobs visible to the authenticated user, ordered by request time.

        Logs the request parameters and returns the filtered queryset.

        Returns:
        - Filtered queryset of jobs.
        """
        user = self.request.user
        logger.info(
            f"user: {user} request the jobs with params: {self.request.query_params}"
        )
        return Job.objects.visible_for_user(user).order_by("-received_request_time")

    @action(detail=False, methods=["post"])
    def recent_scans(self, request):
        """
        Retrieve recent jobs based on an MD5 hash, filtered by a maximum temporal distance.

        Expects the following parameters in the request data:
        - `md5`: The MD5 hash to filter jobs by.
        - `max_temporal_distance`: The maximum number of days to look back for recent jobs (default is 14 days).

        Returns:
        - List of recent jobs matching the MD5 hash.
        """
        if "md5" not in request.data:
            raise ValidationError({"detail": "md5 is required"})
        max_temporal_distance = request.data.get("max_temporal_distance", 14)
        jobs = (
            Job.objects.filter(md5=request.data["md5"])
            .visible_for_user(self.request.user)
            .filter(
                finished_analysis_time__gte=now()
                - datetime.timedelta(days=max_temporal_distance)
            )
            .annotate_importance(request.user)
            .order_by("-importance", "-finished_analysis_time")
        )
        return Response(
            JobRecentScanSerializer(jobs, many=True).data, status=status.HTTP_200_OK
        )

    @action(detail=False, methods=["post"])
    def recent_scans_user(self, request):
        """
        Retrieve recent jobs for the authenticated user, filtered by sample status.

        Expects the following parameters in the request data:
        - `is_sample`: Whether to filter jobs by sample status (required).
        - `limit`: The maximum number of recent jobs to return (default is 5).

        Returns:
        - List of recent jobs for the user.
        """
        limit = request.data.get("limit", 5)
        if "is_sample" not in request.data:
            raise ValidationError({"detail": "is_sample is required"})
        jobs = (
            Job.objects.filter(user__pk=request.user.pk)
            .filter(is_sample=request.data["is_sample"])
            .annotate_importance(request.user)
            .order_by("-importance", "-finished_analysis_time")[:limit]
        )
        return Response(
            JobRecentScanSerializer(jobs, many=True).data, status=status.HTTP_200_OK
        )

    @action(detail=True, methods=["patch"])
    def retry(self, request, pk=None):
        """
        Retry a job if its status is in a final state.

        If the job is currently running, raises a validation error.

        Returns:
        - No content (204) if the job is successfully retried.
        """
        job = self.get_object()
        if job.status not in Job.Status.final_statuses():
            raise ValidationError({"detail": "Job is running"})
        job.retry()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @add_docs(
        description="Kill running job by closing celery tasks and marking as killed",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=True, methods=["patch"])
    def kill(self, request, pk=None):
        """
        Kill a running job by closing celery tasks and marking the job as killed.

        If the job is not running, raises a validation error.

        Returns:
        - No content (204) if the job is successfully killed.
        """
        # get job object or raise 404
        job = self.get_object()

        # check if job running
        if job.status in Job.Status.final_statuses():
            raise ValidationError({"detail": "Job is not running"})
        # close celery tasks and mark reports as killed
        job.kill_if_ongoing()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @add_docs(
        description="Download file/sample associated with a job",
        request=None,
        responses={200: OpenApiTypes.BINARY, 400: None},
    )
    @action(detail=True, methods=["get"])
    def download_sample(self, request, pk=None):
        """
        Download a sample associated with a job.

        If the job does not have a sample, raises a validation error.

        Returns:
        - The file associated with the job as an attachment.

        :param url: pk (job_id)
        :returns: bytes
        """
        # get job object
        job = self.get_object()

        # make sure it is a sample
        if not job.is_sample:
            raise ValidationError(
                {"detail": "Requested job does not have a sample associated with it."}
            )
        return FileResponse(
            job.file,
            filename=job.file_name,
            content_type=job.file_mimetype,
            as_attachment=True,
        )

    @add_docs(description="Pivot a job")
    @action(
        detail=True, methods=["post"]
    )  # , url_path="pivot-(?P<pivot_config_pk>\d+)")
    def pivot(self, request, pk=None, pivot_config_pk=None):
        """
        Perform a pivot operation from a job's reports based on a specified pivot configuration.

        Expects the following parameters:
        - `pivot_config_pk`: The primary key of the pivot configuration to use.

        Returns:
        - List of job IDs created as a result of the pivot.
        """
        starting_job = self.get_object()
        try:
            pivot_config: PivotConfig = PivotConfig.objects.get(pk=pivot_config_pk)
        except PivotConfig.DoesNotExist:
            raise ValidationError({"detail": "Requested pivot config does not exist."})
        else:
            try:
                pivots = pivot_config.pivot_job(starting_job.reports)
            except KeyError:
                msg = (
                    f"Unable to retrieve value at {self.field}"
                    f" from job {starting_job.pk}"
                )
                logger.error(msg)
                raise ValidationError({"detail": msg})
            except Exception as e:
                logger.exception(e)
                raise ValidationError(
                    {"detail": f"Unable to start pivot from job {starting_job.pk}"}
                )
            else:
                return Response(
                    [pivot.ending_job.pk for pivot in pivots],
                    status=status.HTTP_201_CREATED,
                )

    @action(
        url_path="aggregate/status",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_status(self, request):
        """
        Aggregate jobs by their status.

        Returns:
        - Aggregated count of jobs for each status.
        """
        annotations = {
            key.lower(): Count("status", filter=Q(status=key))
            for key in Job.Status.values
        }
        return self.__aggregation_response_static(
            annotations, users=self.get_org_members(request)
        )

    @action(
        url_path="aggregate/type",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_type(self, request):
        """
        Aggregate jobs by type (file or observable).

        Returns:
        - Aggregated count of jobs for each type.
        """
        annotations = {
            "file": Count("is_sample", filter=Q(is_sample=True)),
            "observable": Count("is_sample", filter=Q(is_sample=False)),
        }
        return self.__aggregation_response_static(
            annotations, users=self.get_org_members(request)
        )

    @action(
        url_path="aggregate/observable_classification",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_observable_classification(self, request):
        """
        Aggregate jobs by observable classification.

        Returns:
        - Aggregated count of jobs for each observable classification.
        """
        annotations = {
            oc.lower(): Count(
                "observable_classification", filter=Q(observable_classification=oc)
            )
            for oc in ObservableTypes.values
        }
        return self.__aggregation_response_static(
            annotations, users=self.get_org_members(request)
        )

    @action(
        url_path="aggregate/file_mimetype",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_file_mimetype(self, request):
        """
        Aggregate jobs by file MIME type.

        Returns:
        - Aggregated count of jobs for each MIME type.
        """
        return self.__aggregation_response_dynamic(
            "file_mimetype", users=self.get_org_members(request)
        )

    @action(
        url_path="aggregate/observable_name",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_observable_name(self, request):
        """
        Aggregate jobs by observable name.

        Returns:
        - Aggregated count of jobs for each observable name.
        """
        return self.__aggregation_response_dynamic(
            "observable_name", False, users=self.get_org_members(request)
        )

    @action(
        url_path="aggregate/md5",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_md5(self, request):
        """
        Aggregate jobs by MD5 hash.

        Returns:
        - Aggregated count of jobs for each MD5 hash.
        """
        # this is for file
        return self.__aggregation_response_dynamic(
            "md5", False, users=self.get_org_members(request)
        )

    @staticmethod
    def get_org_members(request):
        """
        Retrieve members of the organization associated with the authenticated user.

        If the 'org' query parameter is set to 'true', this method returns all
        users who are members of the authenticated user's organization.

        Args:
            request: The HTTP request object containing user information and query parameters.

        Returns:
            list or None: A list of users who are members of the user's organization
            if the 'org' query parameter is 'true', otherwise None.
        """
        user = request.user
        org_param = request.GET.get("org", "").lower() == "true"
        users_of_organization = None
        if org_param:
            organization = user.membership.organization
            users_of_organization = [
                membership.user for membership in organization.members.all()
            ]
        return users_of_organization

    def __aggregation_response_static(self, annotations: dict, users=None) -> Response:
        """
        Generate a static aggregation of Job objects filtered by a time range.

        This method applies the provided annotations to aggregate Job objects
        within the specified time range. Optionally, it filters the results by
        the given list of users.

        Args:
            annotations (dict): Annotations to apply for the aggregation.
            users (list, optional): A list of users to filter the Job objects by.

        Returns:
            Response: A Django REST framework Response object containing the aggregated data.
        """
        delta, basis = self.__parse_range(self.request)
        filter_kwargs = {"received_request_time__gte": delta}
        if users:
            filter_kwargs["user__in"] = users
        qs = (
            Job.objects.filter(**filter_kwargs)
            .annotate(date=Trunc("received_request_time", basis))
            .values("date")
            .annotate(**annotations)
        )
        return Response(qs)

    def __aggregation_response_dynamic(
        self,
        field_name: str,
        group_by_date: bool = True,
        limit: int = 5,
        users=None,
    ) -> Response:
        """
        Dynamically aggregate Job objects based on a specified field and time range.

        This method identifies the most frequent values of a given field within
        a specified time range and aggregates the Job objects accordingly.
        Optionally, it can group the results by date and limit the number of
        most frequent values.

        Args:
            field_name (str): The name of the field to aggregate by.
            group_by_date (bool, optional): Whether to group the results by date. Defaults to True.
            limit (int, optional): The maximum number of most frequent values to retrieve. Defaults to 5.
            users (list, optional): A list of users to filter the Job objects by.

        Returns:
            Response: A Django REST framework Response object containing the most frequent values
            and the aggregated data.
        """
        delta, basis = self.__parse_range(self.request)
        filter_kwargs = {"received_request_time__gte": delta}
        if users:
            filter_kwargs["user__in"] = users
        if field_name == "md5":
            filter_kwargs["is_sample"] = True

        most_frequent_values = (
            Job.objects.filter(**filter_kwargs)
            .exclude(**{f"{field_name}__isnull": True})
            .exclude(**{f"{field_name}__exact": ""})
            # excluding those because they could lead to SQL query errors
            .exclude(
                observable_classification__in=[
                    ObservableClassification.URL,
                    ObservableClassification.GENERIC,
                ]
            )
            .annotate(count=Count(field_name))
            .distinct()
            .order_by("-count")[:limit]
            .values_list(field_name, flat=True)
        )

        logger.info(
            f"request: {field_name} found most_frequent_values: {most_frequent_values}"
        )

        if len(most_frequent_values):
            annotations = {
                val: Count(field_name, filter=Q(**{field_name: val}))
                for val in most_frequent_values
            }
            logger.debug(f"request: {field_name} annotations: {annotations}")
            if group_by_date:
                aggregation = (
                    Job.objects.filter(**filter_kwargs)
                    .annotate(date=Trunc("received_request_time", basis))
                    .values("date")
                    .annotate(**annotations)
                )
            else:
                aggregation = Job.objects.filter(**filter_kwargs).aggregate(
                    **annotations
                )
        else:
            aggregation = {}

        return Response(
            {
                "values": most_frequent_values,
                "aggregation": aggregation,
            }
        )

    @staticmethod
    def __parse_range(request):
        """
        Parse the time range from the request query parameters.

        This method attempts to extract the 'range' query parameter from the
        request. If the parameter is not provided, it defaults to '7d' (7 days).

        Args:
            request: The HTTP request object containing query parameters.

        Returns:
            tuple: A tuple containing the parsed time delta and the basis for date truncation.
        """
        try:
            range_str = request.GET["range"]
        except KeyError:
            # default
            range_str = "7d"

        return parse_humanized_range(range_str)


@add_docs(
    description="""
    REST endpoint to perform CRUD operations on ``Tag`` model.
    Requires authentication.
    """
)
class TagViewSet(viewsets.ModelViewSet):
    """
    A viewset that provides CRUD (Create, Read, Update, Delete) operations
    for the ``Tag`` model.

    This viewset leverages Django REST framework's `ModelViewSet` to handle
    requests for the `Tag` model. It includes the default implementations
    for `list`, `retrieve`, `create`, `update`, `partial_update`, and `destroy` actions.

    Attributes:
        queryset (QuerySet): The queryset that retrieves all Tag objects from the database.
        serializer_class (Serializer): The serializer class used to convert Tag model instances to JSON and vice versa.
        pagination_class: Pagination is disabled for this viewset.
    """

    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    pagination_class = None


class ModelWithOwnershipViewSet(viewsets.ModelViewSet):
    """
    A viewset that enforces ownership-based access control for models.

    This class extends the functionality of `ModelViewSet` to restrict access to
    objects based on ownership. It modifies the queryset for the `list` action
    to only include objects visible to the requesting user, and adds custom
    permission checks for `destroy` and `update` actions.

    Methods:
        get_queryset(): Returns the queryset of the model, filtered for visibility
                        to the requesting user during the `list` action.
        get_permissions(): Returns the permissions required for the current action,
                           with additional checks for ownership during `destroy`
                           and `update` actions. Raises `PermissionDenied` for `PUT` requests.
    """

    def get_queryset(self):
        """
        Retrieves the queryset for the viewset, modifying it for the `list` action
        to only include objects visible to the requesting user.

        Returns:
            QuerySet: The queryset of the model, possibly filtered for visibility.
        """
        qs = super().get_queryset()
        if self.action == "list":
            return qs.visible_for_user(self.request.user)
        return qs

    def get_permissions(self):
        """
        Retrieves the permissions required for the current action.

        For the `destroy` and `update` actions, additional checks are performed to
        ensure that only object owners or admins can perform these actions. Raises
        a `PermissionDenied` exception for `PUT` requests.

        Returns:
            list: A list of permission instances.
        """
        permissions = super().get_permissions()
        if self.action in ["destroy", "update"]:
            if self.request.method == "PUT":
                raise PermissionDenied()
            # code quality checker marks this as error, but it works correctly
            permissions.append(
                (  # skipcq: PYL-E1102
                    IsObjectAdminPermission | IsObjectOwnerPermission
                )()
            )

        return permissions


@add_docs(
    description="""
    REST endpoint to fetch list of PluginConfig or retrieve/delete a CustomConfig.
    Requires authentication. Allows access to only authorized CustomConfigs.
    """
)
class PluginConfigViewSet(ModelWithOwnershipViewSet):
    """
    A viewset for managing `PluginConfig` objects with ownership-based access control.

    This viewset extends `ModelWithOwnershipViewSet` to handle `PluginConfig` objects,
    allowing users to list, retrieve, and delete configurations while ensuring that only
    authorized configurations are accessible. It customizes the queryset to exclude default
    values and orders the configurations by ID.

    Attributes:
        serializer_class (class): The serializer class used for `PluginConfig` objects.
        pagination_class (class): Specifies that pagination is not applied.
        queryset (QuerySet): The queryset for `PluginConfig` objects, initially set to all objects.

    Methods:
        get_queryset(): Returns the queryset for `PluginConfig` objects, excluding default values
                        (where the owner is `NULL`) and ordering the remaining objects by ID.
    """

    serializer_class = PluginConfigSerializer
    pagination_class = None
    queryset = PluginConfig.objects.all()

    def get_queryset(self):
        """
        Retrieves the queryset for `PluginConfig` objects, excluding those with default values
        (where the owner is `NULL`) and ordering the remaining objects by ID.

        Returns:
            QuerySet: The filtered and ordered queryset of `PluginConfig` objects.
        """
        # the .exclude is to remove the default values
        return super().get_queryset().exclude(owner__isnull=True).order_by("id")


@add_docs(
    description="""This endpoint allows organization owners
    and members to view plugin state.""",
    responses={
        200: inline_serializer(
            name="PluginStateViewerResponseSerializer",
            fields={
                "data": rfs.JSONField(),
            },
        ),
    },
)
@api_view(["GET"])
def plugin_state_viewer(request):
    """
    View to retrieve the state of plugin configurations for the requesting user’s organization.

    This endpoint is accessible only to users with an active membership in an organization.
    It returns a JSON response with the state of each plugin configuration, specifically
    indicating whether each plugin is disabled.

    Args:
        request (HttpRequest): The request object containing the HTTP GET request.

    Returns:
        Response: A JSON response with the state of each plugin configuration,
                  indicating whether it is disabled or not.

    Raises:
        PermissionDenied: If the requesting user does not belong to any organization.
    """
    if not request.user.has_membership():
        raise PermissionDenied()

    result = {"data": {}}
    for opc in OrganizationPluginConfiguration.objects.filter(disabled=True):
        result["data"][opc.config.name] = {
            "disabled": True,
        }
    return Response(result)


class PythonReportActionViewSet(viewsets.GenericViewSet, metaclass=ABCMeta):
    """
    A base view set for handling actions related to plugin reports.

    This view set provides methods for killing and retrying plugin reports,
    and requires users to have appropriate permissions based on the
    `IsObjectUserOrSameOrgPermission`.

    Attributes:
        permission_classes (list): List of permission classes to apply.

    Methods:
    get_queryset: Returns the queryset of reports based on the model class.
    get_object: Retrieves a specific report object by job_id and report_id.
    perform_kill: Kills a running plugin by terminating its Celery task and marking it as killed.
    perform_retry: Retries a failed or killed plugin run.
    kill: Handles the endpoint to kill a specific report.
    retry: Handles the endpoint to retry a specific report.

    """

    permission_classes = [
        IsObjectUserOrSameOrgPermission,
    ]

    @classmethod
    @property
    @abstractmethod
    def report_model(cls):
        """
        Abstract property that should return the model class for the report.

        Subclasses must implement this property to specify the model
        class for the reports being handled by this view set.

        Returns:
            Type[AbstractReport]: The model class for the report.

        Raises:
            NotImplementedError: If not overridden by a subclass.
        """
        raise NotImplementedError()

    def get_queryset(self):
        """
        Returns the queryset of reports based on the model class.

        Filters the queryset to return all instances of the report model.

        Returns:
            QuerySet: A queryset of all report instances.
        """
        return self.report_model.objects.all()

    def get_object(self, job_id: int, report_id: int) -> AbstractReport:
        """
        Retrieves a specific report object by job_id and report_id.

        Overrides the drf's default `get_object` method to fetch a report object
        based on job_id and report_id, and checks the permissions for the object.

        Args:
            job_id (int): The ID of the job associated with the report.
            report_id (int): The ID of the report.

        Returns:
            AbstractReport: The report object.

        Raises:
            NotFound: If the report does not exist.
        """
        try:
            obj = self.report_model.objects.get(
                job_id=job_id,
                pk=report_id,
            )
        except self.report_model.DoesNotExist:
            raise NotFound()
        else:
            self.check_object_permissions(self.request, obj)
            return obj

    @staticmethod
    def perform_kill(report: AbstractReport):
        """
        Kills a running plugin by terminating its Celery task and marking it as killed.

        This method is a callback for performing additional actions after a
        kill operation, including updating the report status and cleaning up
        the associated job.

        Args:
            report (AbstractReport): The report to be killed.
        """
        # kill celery task
        celery_app.control.revoke(report.task_id, terminate=True)
        # update report
        report.status = AbstractReport.Status.KILLED
        report.save(update_fields=["status"])
        # clean up job

        job = Job.objects.get(pk=report.job.pk)
        job.set_final_status()
        JobConsumer.serialize_and_send_job(job)

    @staticmethod
    def perform_retry(report: AbstractReport):
        """
        Retries a failed or killed plugin run.

        This method clears the errors and re-runs the plugin with the same arguments.
        It fetches the appropriate task signature and schedules the job again.

        Args:
            report (AbstractReport): The report to be retried.

        Raises:
            RuntimeError: If unable to find a valid task signature for the report.
        """
        report.errors.clear()
        report.save(update_fields=["errors"])
        try:
            signature = next(
                report.config.__class__.objects.filter(pk=report.config.pk)
                .annotate_runnable(report.job.user)
                .get_signatures(
                    report.job,
                )
            )
        except StopIteration:
            raise RuntimeError(f"Unable to find signature for report {report.pk}")
        runner = signature | tasks.job_set_final_status.signature(
            args=[report.job.id],
            kwargs={},
            queue=report.config.queue,
            immutable=True,
            MessageGroupId=str(uuid.uuid4()),
            priority=report.job.priority,
        )
        runner()

    @add_docs(
        description="Kill running plugin by closing celery task and marking as killed",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=False, methods=["patch"])
    def kill(self, request, job_id, report_id):
        """
        Kills a specific report by terminating its Celery task and marking it as killed.

        This endpoint handles the patch request to kill a report if its status is
        running or pending.

        Args:
            request (HttpRequest): The request object containing the HTTP PATCH request.
            job_id (int): The ID of the job associated with the report.
            report_id (int): The ID of the report.

        Returns:
            Response: HTTP 204 No Content if successful.

        Raises:
            ValidationError: If the report is not in a valid state for killing.
        """
        logger.info(
            f"kill request from user {request.user}"
            f" for job_id {job_id}, pk {report_id}"
        )
        # get report object or raise 404
        report = self.get_object(job_id, report_id)
        if report.status not in [
            AbstractReport.Status.RUNNING,
            AbstractReport.Status.PENDING,
        ]:
            raise ValidationError({"detail": "Plugin is not running or pending"})

        self.perform_kill(report)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @add_docs(
        description="Retry a plugin run if it failed/was killed previously",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=False, methods=["patch"])
    def retry(self, request, job_id, report_id):
        """
        Retries a failed or killed plugin run.

        This method clears the errors and re-runs the plugin with the same arguments.
        It fetches the appropriate task signature and schedules the job again.

        Args:
            report (AbstractReport): The report to be retried.

        Raises:
            RuntimeError: If unable to find a valid task signature for the report.
        """
        logger.info(
            f"retry request from user {request.user}"
            f" for job_id {job_id}, report_id {report_id}"
        )
        # get report object or raise 404
        report = self.get_object(job_id, report_id)
        if report.status not in [
            AbstractReport.Status.FAILED,
            AbstractReport.Status.KILLED,
        ]:
            raise ValidationError(
                {"detail": "Plugin status should be failed or killed"}
            )

        # retry with the same arguments
        try:
            self.perform_retry(report)
        except StopIteration:
            logger.exception(f"Unable to find signature for report {report.pk}")
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(status=status.HTTP_204_NO_CONTENT)


class AbstractConfigViewSet(
    PaginationMixin, viewsets.ReadOnlyModelViewSet, metaclass=ABCMeta
):
    """
    A base view set for handling plugin configuration actions.

    This view set provides methods for enabling and disabling plugins
    within an organization. It requires users to be authenticated and
    to have appropriate permissions.

    Attributes:
        permission_classes (list): List of permission classes to apply.
        ordering (list): Default ordering for the queryset.
        lookup_field (str): Field to look up in the URL.

    Methods:
        disable_in_org(request, name=None):
            Disables the plugin for the organization of the authenticated user.
        enable_in_org(request, name=None):
            Enables the plugin for the organization of the authenticated user.
    """

    permission_classes = [IsAuthenticated]
    ordering = ["name"]
    lookup_field = "name"

    @add_docs(
        description="Disable/Enable plugin for your organization",
        request=None,
        responses={201: {}, 202: {}},
    )
    @action(
        methods=["post"],
        detail=True,
        url_path="organization",
    )
    def disable_in_org(self, request, name=None):
        """
        Disables the plugin for the organization of the authenticated user.

        Only organization admins can disable the plugin. If the plugin is
        already disabled, a validation error is raised.

        Args:
            request (Request): The HTTP request object.
            name (str, optional): The name of the plugin. Defaults to None.

        Returns:
            Response: HTTP response indicating the success or failure of the operation.
        """
        logger.info(f"get disable_in_org from user {request.user}, name {name}")
        obj: AbstractConfig = self.get_object()
        if request.user.has_membership():
            if not request.user.membership.is_admin:
                raise PermissionDenied()
        else:
            raise PermissionDenied()
        organization = request.user.membership.organization
        org_configuration = obj.get_or_create_org_configuration(organization)
        if org_configuration.disabled:
            raise ValidationError({"detail": f"Plugin {obj.name} already disabled"})
        org_configuration.disable_manually(request.user)
        return Response(status=status.HTTP_201_CREATED)

    @disable_in_org.mapping.delete
    def enable_in_org(self, request, name=None):
        """
        Enables the plugin for the organization of the authenticated user.

        Only organization admins can enable the plugin. If the plugin is
        already enabled, a validation error is raised.

        Args:
            request (Request): The HTTP request object.
            name (str, optional): The name of the plugin. Defaults to None.

        Returns:
            Response: HTTP response indicating the success or failure of the operation.
        """
        logger.info(f"get enable_in_org from user {request.user}, name {name}")
        obj: AbstractConfig = self.get_object()
        if request.user.has_membership():
            if not request.user.membership.is_admin:
                raise PermissionDenied()
        else:
            raise PermissionDenied()
        organization = request.user.membership.organization
        org_configuration = obj.get_or_create_org_configuration(organization)
        if not org_configuration.disabled:
            raise ValidationError({"detail": f"Plugin {obj.name} already enabled"})
        org_configuration.enable_manually(request.user)
        return Response(status=status.HTTP_202_ACCEPTED)


class PythonConfigViewSet(AbstractConfigViewSet):
    """
    A view set for handling actions related to Python plugin configurations.

    This view set provides methods to perform health checks and pull updates
    for Python-based plugins. It inherits from `AbstractConfigViewSet` and
    requires users to be authenticated.

    Attributes:
        serializer_class (class): Serializer class for the view set.

    Methods:
        health_check(request, name=None):
            Checks if the server instance associated with the plugin is up.
        pull(request, name=None):
            Pulls updates for the plugin.
    """

    serializer_class = PythonConfigSerializer

    def get_queryset(self):
        """
        Returns a queryset of all PythonConfig instances with related
        python_module parameters pre-fetched.

        Returns:
            QuerySet: A queryset of PythonConfig instances.
        """
        return self.serializer_class.Meta.model.objects.all().prefetch_related(
            "python_module__parameters"
        )

    @add_docs(
        description="Health Check: "
        "if server instance associated with plugin is up or not",
        request=None,
        responses={
            200: inline_serializer(
                name="PluginHealthCheckSuccessResponse",
                fields={
                    "status": rfs.BooleanField(allow_null=True),
                },
            ),
        },
    )
    @action(
        methods=["get"],
        detail=True,
        url_path="health_check",
    )
    def health_check(self, request, name=None):
        """
        Checks the health of the server instance associated with the plugin.

        This method attempts to check if the plugin's server instance is
        up and running. It uses the `health_check` method of the plugin's
        Python class.

        Args:
            request (Request): The HTTP request object.
            name (str, optional): The name of the plugin. Defaults to None.

        Returns:
            Response: HTTP response with the health status of the plugin.

        Raises:
            ValidationError: If no health check is implemented or if an
                             unexpected exception occurs.
        """
        logger.info(f"get healthcheck from user {request.user}, name {name}")
        config: PythonConfig = self.get_object()
        python_obj = config.python_module.python_class(config)
        try:
            health_status = python_obj.health_check(request.user)
        except NotImplementedError as e:
            logger.info(f"NotImplementedError {e}, user {request.user}, name {name}")
            raise ValidationError({"detail": "No healthcheck implemented"})
        except Exception as e:
            logger.exception(e)
            raise ValidationError(
                {"detail": "Unexpected exception raised. Check the code."}
            )
        else:
            return Response(data={"status": health_status}, status=status.HTTP_200_OK)

    @action(
        methods=["post"],
        detail=True,
        url_path="pull",
    )
    def pull(self, request, name=None):
        """
        Pulls updates for the plugin.

        This method attempts to pull updates for the plugin by calling
        the `update` method of the plugin's Python class. It also handles
        any exceptions that occur during this process.

        Args:
            request (Request): The HTTP request object.
            name (str, optional): The name of the plugin. Defaults to None.

        Returns:
            Response: HTTP response with the update status of the plugin.

        Raises:
            ValidationError: If the update is not implemented or if an
                             unexpected exception occurs.
        """
        logger.info(f"post pull from user {request.user}, name {name}")
        obj: PythonConfig = self.get_object()
        python_obj = obj.python_module.python_class(obj)
        try:
            update_status = python_obj.update()
        except NotImplementedError as e:
            raise ValidationError({"detail": str(e)})
        except Exception as e:
            logger.exception(e)
            raise ValidationError(
                {"detail": "Unexpected exception raised. Check the code."}
            )
        else:
            if update_status is None:
                raise ValidationError(
                    {"detail": "This Plugin has no Update implemented"}
                )
            return Response(data={"status": update_status}, status=status.HTTP_200_OK)
