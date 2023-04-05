# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from django.db.models import Count, Q
from django.db.models.functions import Trunc
from django.http import FileResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from certego_saas.apps.organization.permissions import (
    IsObjectOwnerOrSameOrgPermission,
    IsObjectOwnerPermission,
)
from certego_saas.ext.helpers import cache_action_response, parse_humanized_range
from certego_saas.ext.mixins import SerializerActionMixin
from certego_saas.ext.viewsets import ReadAndDeleteOnlyViewSet

from .analyzers_manager.constants import ObservableTypes
from .choices import ObservableClassification
from .core.models import AbstractConfig
from .filters import JobFilter
from .models import Comment, Job, PluginConfig, Tag
from .serializers import (
    CommentSerializer,
    FileAnalysisSerializer,
    JobAvailabilitySerializer,
    JobListSerializer,
    JobResponseSerializer,
    JobSerializer,
    ObservableAnalysisSerializer,
    PluginConfigSerializer,
    TagSerializer,
)

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
@api_view(["POST"])
def ask_analysis_availability(request):
    serializer = JobAvailabilitySerializer(
        data=request.data, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    try:
        job = serializer.save()
    except Job.DoesNotExist:
        result = []
    else:
        result = [job]
    return Response(
        JobResponseSerializer(result, many=True).data,
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
    return Response(
        JobResponseSerializer(result, many=True).data,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="This endpoint allows to start a Job related for a single File."
    " Retained for retro-compatibility",
    request=FileAnalysisSerializer,
    responses={200: JobResponseSerializer(many=True)},
)
@api_view(["POST"])
def analyze_file(request):
    fas = FileAnalysisSerializer(data=request.data, context={"request": request})
    fas.is_valid(raise_exception=True)
    job = fas.save(send_task=True)
    return Response(
        JobResponseSerializer(job).data,
        status=status.HTTP_200_OK,
    )


@add_docs(
    description="This endpoint allows to start Jobs related to multiple Files",
    # It should be better to link the doc to the related MultipleFileAnalysisSerializer.
    # It is not straightforward because you can't just add a class
    # which extends a ListSerializer.
    # Follow this doc to try to find a fix:
    # https://drf-spectacular.readthedocs.io/en/latest/customization.html#declare-serializer-magic-with-openapiserializerextension
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
    fas = FileAnalysisSerializer(
        data=request.data, context={"request": request}, many=True
    )
    fas.is_valid(raise_exception=True)
    jobs = fas.save(send_task=True)
    return Response(
        JobResponseSerializer(jobs, many=True).data,
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

    oas = ObservableAnalysisSerializer(data=request.data, context={"request": request})
    oas.is_valid(raise_exception=True)
    job = oas.save(send_task=True)
    return Response(
        JobResponseSerializer(job).data,
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
    oas = ObservableAnalysisSerializer(
        data=request.data, many=True, context={"request": request}
    )
    oas.is_valid(raise_exception=True)
    jobs = oas.save(send_task=True)
    return Response(
        JobResponseSerializer(jobs, many=True).data,
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
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        permissions = super().get_permissions()

        # only the owner of the comment can update or delete the comment
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(IsObjectOwnerPermission())
        # the owner and anyone in the org can read the comment
        if self.action in ["retrieve"]:
            permissions.append(IsObjectOwnerOrSameOrgPermission())

        return permissions

    def get_queryset(self):
        queryset = super().get_queryset()
        jobs = Job.visible_for_user(self.request.user).values_list("pk", flat=True)
        return queryset.filter(job__id__in=jobs)


@add_docs(
    description="""
    REST endpoint to fetch list of jobs or retrieve/delete a job with job ID.
    Requires authentication.
    """
)
class JobViewSet(ReadAndDeleteOnlyViewSet, SerializerActionMixin):
    queryset = (
        Job.objects.prefetch_related("tags").order_by("-received_request_time").all()
    )
    serializer_class = JobSerializer
    serializer_action_classes = {
        "retrieve": JobSerializer,
        "list": JobListSerializer,
    }
    filterset_class = JobFilter
    ordering_fields = [
        "received_request_time",
        "finished_analysis_time",
        "process_time",
    ]

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy", "kill"]:
            permissions.append(IsObjectOwnerOrSameOrgPermission())
        return permissions

    def get_queryset(self):
        user = self.request.user
        logger.info(
            f"user: {user} request the jobs with params: {self.request.query_params}"
        )
        return (
            Job.visible_for_user(user)
            .prefetch_related("tags")
            .order_by("-received_request_time")
        )

    @add_docs(
        description="Kill running job by closing celery tasks and marking as killed",
        request=None,
        responses={
            204: None,
        },
    )
    @action(detail=True, methods=["patch"])
    def kill(self, request, pk=None):
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
        Download a sample from a given Job ID.

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

    @action(
        url_path="aggregate/status",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_status(self, request):
        annotations = {
            key.lower(): Count("status", filter=Q(status=key))
            for key in Job.Status.values
        }
        return self.__aggregation_response_static(annotations)

    @action(
        url_path="aggregate/type",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_type(self, request):
        annotations = {
            "file": Count("is_sample", filter=Q(is_sample=True)),
            "observable": Count("is_sample", filter=Q(is_sample=False)),
        }
        return self.__aggregation_response_static(annotations)

    @action(
        url_path="aggregate/observable_classification",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_observable_classification(self, request):
        annotations = {
            oc.lower(): Count(
                "observable_classification", filter=Q(observable_classification=oc)
            )
            for oc in ObservableTypes.values
        }
        return self.__aggregation_response_static(annotations)

    @action(
        url_path="aggregate/file_mimetype",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_file_mimetype(self, request):
        return self.__aggregation_response_dynamic("file_mimetype")

    @action(
        url_path="aggregate/observable_name",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_observable_name(self, request):
        return self.__aggregation_response_dynamic("observable_name", False)

    @action(
        url_path="aggregate/md5",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_md5(self, request):
        # this is for file
        return self.__aggregation_response_dynamic("md5", False)

    def __aggregation_response_static(self, annotations: dict) -> Response:
        delta, basis = self.__parse_range(self.request)
        qs = (
            Job.objects.filter(received_request_time__gte=delta)
            .annotate(date=Trunc("received_request_time", basis))
            .values("date")
            .annotate(**annotations)
        )
        return Response(qs)

    def __aggregation_response_dynamic(
        self, field_name: str, group_by_date: bool = True, limit: int = 5
    ) -> Response:
        delta, basis = self.__parse_range(self.request)

        filter_kwargs = {"received_request_time__gte": delta}
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
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    pagination_class = None


@add_docs(
    description="""
    REST endpoint to fetch list of PluginConfig or retrieve/delete a CustomConfig.
    Requires authentication. Allows access to only authorized CustomConfigs.
    """
)
class PluginConfigViewSet(viewsets.ModelViewSet):
    queryset = PluginConfig.objects.filter(
        config_type=PluginConfig.ConfigType.PARAMETER
    ).order_by("id")
    serializer_class = PluginConfigSerializer
    pagination_class = None

    def get_queryset(self):
        return PluginConfig.visible_for_user(self.request.user).order_by("id")


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
    from api_app.analyzers_manager.models import AnalyzerConfig
    from api_app.connectors_manager.models import ConnectorConfig
    from api_app.visualizers_manager.models import VisualizerConfig

    if not request.user.has_membership():
        raise PermissionDenied()

    result = {"data": {}}

    classes = [AnalyzerConfig, ConnectorConfig, VisualizerConfig]
    for Class_ in classes:
        for plugin in Class_.objects.all():
            plugin: AbstractConfig
            if plugin.disabled_in_organizations.filter(
                pk=request.user.membership.organization.pk
            ).exists():
                result["data"][plugin.name] = {
                    "disabled": True,
                    "plugin_type": plugin.plugin_type,
                }
    return Response(result)
