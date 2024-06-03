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
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        permissions = super().get_permissions()

        # only the owner of the comment can update or delete the comment
        if self.action in ["destroy", "update", "partial_update"]:
            permissions.append(IsObjectUserPermission())
        # the owner and anyone in the org can read the comment
        if self.action in ["retrieve"]:
            permissions.append(IsObjectUserOrSameOrgPermission())

        return permissions

    def get_queryset(self):
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
        permissions = super().get_permissions()
        if self.action in ["destroy", "kill"]:
            permissions.append(IsObjectUserOrSameOrgPermission())
        return permissions

    def get_queryset(self):
        user = self.request.user
        logger.info(
            f"user: {user} request the jobs with params: {self.request.query_params}"
        )
        return Job.objects.visible_for_user(user).order_by("-received_request_time")

    @action(detail=False, methods=["post"])
    def recent_scans(self, request):
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

    @add_docs(description="Pivot a job")
    @action(
        detail=True, methods=["post"]
    )  # , url_path="pivot-(?P<pivot_config_pk>\d+)")
    def pivot(self, request, pk=None, pivot_config_pk=None):
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
        # this is for file
        return self.__aggregation_response_dynamic(
            "md5", False, users=self.get_org_members(request)
        )

    @staticmethod
    def get_org_members(request):
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


class ModelWithOwnershipViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        qs = super().get_queryset()
        if self.action == "list":
            return qs.visible_for_user(self.request.user)
        return qs

    def get_permissions(self):
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
    serializer_class = PluginConfigSerializer
    pagination_class = None
    queryset = PluginConfig.objects.all()

    def get_queryset(self):
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
    if not request.user.has_membership():
        raise PermissionDenied()

    result = {"data": {}}
    for opc in OrganizationPluginConfiguration.objects.filter(disabled=True):
        result["data"][opc.config.name] = {
            "disabled": True,
        }
    return Response(result)


class PythonReportActionViewSet(viewsets.GenericViewSet, metaclass=ABCMeta):
    permission_classes = [
        IsObjectUserOrSameOrgPermission,
    ]

    @classmethod
    @property
    @abstractmethod
    def report_model(cls):
        raise NotImplementedError()

    def get_queryset(self):
        return self.report_model.objects.all()

    def get_object(self, job_id: int, report_id: int) -> AbstractReport:
        """
        overrides drf's get_object
        get plugin report object by name and job_id
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
        performs kill
         override for callbacks after kill operation
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
    serializer_class = PythonConfigSerializer

    def get_queryset(self):
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
