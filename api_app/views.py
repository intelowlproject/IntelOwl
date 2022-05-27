# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import copy
import logging
from datetime import timedelta
from typing import Union

from django.conf import settings
from django.db.models import Count, Q
from django.db.models.functions import Trunc
from django.http import FileResponse
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer
from rest_framework import serializers as rfs
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission
from certego_saas.ext.helpers import cache_action_response, parse_humanized_range
from certego_saas.ext.mixins import SerializerActionMixin
from certego_saas.ext.viewsets import ReadAndDeleteOnlyViewSet
from intel_owl.celery import app as celery_app

from .analyzers_manager import controller as analyzers_controller
from .analyzers_manager.constants import ObservableTypes
from .connectors_manager import controller as connectors_controller
from .filters import JobFilter
from .helpers import get_now
from .models import TLP, Job, Status, Tag
from .serializers import (
    AnalysisResponseSerializer,
    FileAnalysisSerializer,
    JobAvailabilitySerializer,
    JobListSerializer,
    JobSerializer,
    ObservableAnalysisSerializer,
    TagSerializer,
)

logger = logging.getLogger(__name__)


def _process_analysis_request(
    data: dict,
    user,
    serializer_class: Union[FileAnalysisSerializer, ObservableAnalysisSerializer],
    warnings: list,
):
    # serialize request data and validate
    serializer = serializer_class(data=data)
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
        user=user,
        analyzers_to_execute=cleaned_analyzer_list,
        connectors_to_execute=cleaned_connectors_list,
    )

    logger.info(f"New Job added to queue <- {repr(job)}.")

    # Check if task is test or not
    if not settings.STAGE_CI:
        # fire celery task
        celery_app.send_task(
            "start_analyzers",
            kwargs=dict(
                job_id=job.pk,
                analyzers_to_execute=cleaned_analyzer_list,
                runtime_configuration=runtime_configuration,
            ),
        )

    ser = AnalysisResponseSerializer(
        data={
            "status": "accepted",
            "job_id": job.pk,
            "warnings": warnings,
            "analyzers_running": cleaned_analyzer_list,
            "connectors_running": cleaned_connectors_list,
        }
    )
    ser.is_valid(raise_exception=True)

    return ser.data


def _individual_analysis_request(
    request,
    serializer_class: Union[FileAnalysisSerializer, ObservableAnalysisSerializer],
):
    """
    Prepare and send file/observable for analysis
    """
    warnings = []
    logger.info(
        f"_individual_analysis_request {serializer_class} "
        f"received request from {request.user}."
        f"Data:{dict(request.data)}."
    )

    response_dict = _process_analysis_request(
        request.data, request.user, serializer_class, warnings
    )

    logger.debug(response_dict)

    return Response(
        response_dict,
        status=status.HTTP_200_OK,
    )


def _multiple_analysis_requests(
    request,
    serializer_class: Union[FileAnalysisSerializer, ObservableAnalysisSerializer],
):
    """
    Prepare and send multiple files/observables for analysis
    """
    warnings = []
    logger.info(
        f"_multiple_analysis_request {serializer_class} "
        f"received request from {request.user}."
        f"Data:{dict(request.data)}."
    )
    responses = []

    common_data = dict(request.data)
    common_data.pop("observables", None)
    for classification, name in request.data.get("observables"):
        data = copy.deepcopy(common_data)
        data["observable_name"] = name
        data["observable_classification"] = classification
        responses.append(
            _process_analysis_request(data, request.user, serializer_class, warnings)
        )

    logger.debug(responses)

    payload = {
        "count": len(responses),
        "results": responses,
    }

    return Response(
        payload,
        status=status.HTTP_200_OK,
    )


""" REST API endpoints """


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
    data_received = request.data
    logger.info(
        f"ask_analysis_availability received request from {str(request.user)}."
        f"Data: {dict(data_received)}"
    )

    serializer = JobAvailabilitySerializer(
        data=data_received, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)
    serialized_data = serializer.validated_data

    analyzers, running_only, md5, minutes_ago = (
        serialized_data["analyzers"],
        serialized_data["running_only"],
        serialized_data["md5"],
        serialized_data["minutes_ago"],
    )

    if running_only:
        statuses_to_check = [Status.RUNNING]
    else:
        statuses_to_check = [
            Status.RUNNING,
            Status.REPORTED_WITHOUT_FAILS,
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

    if minutes_ago:
        minutes_ago_time = get_now() - timedelta(minutes=minutes_ago)
        query = query & Q(received_request_time__gte=minutes_ago_time)

    try:
        last_job_for_md5 = Job.objects.filter(query).latest("received_request_time")
        response_dict = {
            "status": last_job_for_md5.status,
            "job_id": str(last_job_for_md5.id),
            "analyzers_to_execute": last_job_for_md5.analyzers_to_execute,
        }
    except Job.DoesNotExist:
        response_dict = {"status": "not_available"}

    logger.debug(response_dict)

    return Response(response_dict, status=status.HTTP_200_OK)


@add_docs(
    description="This endpoint allows to start a Job related to a file",
    request=FileAnalysisSerializer,
    responses={200: AnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_file(request):
    return _individual_analysis_request(request, FileAnalysisSerializer)


@add_docs(
    description="This endpoint allows to start a Job related to an observable",
    request=ObservableAnalysisSerializer,
    responses={200: AnalysisResponseSerializer},
)
@api_view(["POST"])
def analyze_observable(request):
    return _individual_analysis_request(request, ObservableAnalysisSerializer)


# @add_docs(
#     description="This endpoint allows to start Jobs related to multiple observables",
#     request=ObservableAnalysisSerializer,
# )
@api_view(["POST"])
def analyze_multiple_observables(request):
    return _multiple_analysis_requests(request, ObservableAnalysisSerializer)


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
    filter_class = JobFilter
    ordering_fields = [
        "received_request_time",
        "finished_analysis_time",
    ]

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action in ["destroy", "kill"]:
            permissions.append(IsObjectOwnerOrSameOrgPermission())
        return permissions

    def get_queryset(self):
        """
        User has access to:
        - jobs with TLP = WHITE or GREEN
        - jobs with TLP = AMBER or RED and
        created by a member of their organization.
        """
        queryset = super().get_queryset()
        user = self.request.user
        if user.has_membership():
            user_query = Q(user=user) | Q(
                user__membership__organization_id=user.membership.organization_id
            )
        else:
            user_query = Q(user=user)
        query = Q(tlp__in=[TLP.WHITE, TLP.GREEN]) | (
            Q(tlp__in=[TLP.AMBER, TLP.RED]) & (user_query)
        )
        queryset = queryset.filter(query)
        return queryset

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
        if job.status != "running":
            raise ValidationError({"detail": "Job is not running"})
        # close celery tasks and mark reports as killed
        analyzers_controller.kill_ongoing_analysis(job)
        # set job status
        job.update_status("killed")

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
        url_path="aggregate/file_name",
        detail=False,
        methods=["GET"],
    )
    @cache_action_response(timeout=60 * 5)
    def aggregate_file_name(self, request):
        return self.__aggregation_response_dynamic("file_name", False)

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

        most_frequent_values = (
            Job.objects.filter(received_request_time__gte=delta)
            .exclude(**{f"{field_name}__isnull": True})
            .exclude(**{f"{field_name}__exact": ""})
            .annotate(count=Count(field_name))
            .distinct()
            .order_by("-count")[:limit]
            .values_list(field_name, flat=True)
        )

        if len(most_frequent_values):
            annotations = {
                val: Count(field_name, filter=Q(**{field_name: val}))
                for val in most_frequent_values
            }
            if group_by_date:
                aggregation = (
                    Job.objects.filter(received_request_time__gte=delta)
                    .annotate(date=Trunc("received_request_time", basis))
                    .values("date")
                    .annotate(**annotations)
                )
            else:
                aggregation = Job.objects.filter(
                    received_request_time__gte=delta
                ).aggregate(**annotations)
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
