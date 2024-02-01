# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from django.core.exceptions import BadRequest
from django.http import HttpRequest
from rest_framework import mixins, status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from certego_saas.apps.organization.permissions import IsObjectOwnerOrSameOrgPermission

from ..models import Job
from .models import Analysis
from .serializers import AnalysisSerializer, AnalysisTreeSerializer

logger = logging.getLogger(__name__)


class AnalysisViewSet(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.ListModelMixin,
    GenericViewSet,
):
    permission_classes = [IsAuthenticated, IsObjectOwnerOrSameOrgPermission]
    serializer_class = AnalysisSerializer
    ordering = ["name"]
    lookup_field = "pk"

    def get_object(self):
        obj = super().get_object()
        if not obj.for_organization and obj.owner != self.request.user:
            raise PermissionDenied("You can't use other people private analyses")
        return obj

    def _get_job(self, request):
        try:
            job_pk = request.POST["job"]
        except KeyError:
            raise BadRequest("You should set the `job` argument in the data")
        try:
            job = Job.objects.get(pk=job_pk)
        except Job.DoesNotExist:
            raise BadRequest(f"Job {job_pk} does not exist")
        return job

    def _check_job_and_analysis(self, job, analysis):
        if (
            # same organization if analysis is at org level
            analysis.for_organization
            and (
                job.user.has_membership()
                and analysis.owner.has_membership()
                and job.user.organization == analysis.owner.organization
            )
            # or same user
        ) or job.user == analysis.owner:
            return True
        raise PermissionDenied(
            "You do not have permissions to add this job to the analysis"
        )

    @action(methods=["POST"], url_name="add_job", detail=True)
    def add_job(self, request, pk):
        obj: Analysis = self.get_object()
        job = self._get_job(request)
        self._check_job_and_analysis(job, obj)
        if job.analysis is None:
            job.analysis = obj
            job.save()
            return Response(
                status=status.HTTP_200_OK, data=AnalysisSerializer(instance=obj).data
            )

        elif job.analysis_id == obj.id:
            raise BadRequest("Job is already part of this analysis")
        else:
            raise BadRequest("Job is already part of different analysis")

    @action(methods=["POST"], url_name="remove_job", detail=True)
    def remove_job(self, request, pk):
        obj: Analysis = self.get_object()
        request: HttpRequest
        job = self._get_job(request)
        self._check_job_and_analysis(job, obj)
        if job.analysis_id != obj.pk:
            raise BadRequest(f"You can't remove job {job.id} from analysis")
        job.analysis = None
        job.save()
        return Response(
            status=status.HTTP_200_OK, data=AnalysisSerializer(instance=obj).data
        )

    @action(methods=["POST"], url_name="conclude", detail=True)
    def conclude(self, request, pk):
        obj: Analysis = self.get_object()
        obj.conclude()
        return Response(status=status.HTTP_200_OK)

    @action(methods=["GET"], url_name="graph", detail=True)
    def graph(self, request, pk):
        obj: Analysis = self.get_object()
        return Response(
            status=status.HTTP_200_OK, data=AnalysisTreeSerializer(instance=obj).data
        )
