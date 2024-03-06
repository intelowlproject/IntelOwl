# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from django.http import HttpRequest
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from ..models import Job
from ..permissions import IsObjectOwnerOrSameOrgPermission
from ..views import ModelWithOwnershipViewSet
from .filters import AnalysisFilter
from .models import Analysis
from .serializers import AnalysisSerializer, AnalysisTreeSerializer

logger = logging.getLogger(__name__)


class AnalysisViewSet(ModelWithOwnershipViewSet, ModelViewSet):
    permission_classes = [IsAuthenticated, IsObjectOwnerOrSameOrgPermission]
    serializer_class = AnalysisSerializer
    ordering = ["-start_time"]
    queryset = Analysis.objects.all()
    filterset_class = AnalysisFilter
    ordering_fields = [
        "start_time",
        "end_time",
    ]

    def get_queryset(self):
        return super().get_queryset().prefetch_related("jobs")

    def get_object(self):
        obj = super().get_object()
        if not obj.for_organization and obj.owner != self.request.user:
            raise PermissionDenied("You can't use other people private analyses")
        return obj

    def _get_job(self, request):
        try:
            job_pk = request.data.get("job")
        except KeyError:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": "You should set the `job` argument in the data"},
            )
        try:
            job = Job.objects.get(pk=job_pk)
        except Job.DoesNotExist:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": f"Job {job_pk} does not exist"},
            )
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
        analysis: Analysis = self.get_object()
        job: Job = self._get_job(request)
        self._check_job_and_analysis(job, analysis)
        if job.analysis is None:
            job.analysis = analysis
            job.save()
            # we are possibly changing the status of the analysis
            job.analysis.set_correct_status(save=True)

            return Response(
                status=status.HTTP_200_OK,
                data=AnalysisSerializer(instance=analysis).data,
            )

        elif job.analysis_id == analysis.id:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": "Job is already part of this analysis"},
            )
        else:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": "Job is already part of different analysis"},
            )

    @action(methods=["POST"], url_name="remove_job", detail=True)
    def remove_job(self, request, pk):
        analysis: Analysis = self.get_object()
        request: HttpRequest
        job: Job = self._get_job(request)
        self._check_job_and_analysis(job, analysis)
        if job.analysis_id != analysis.pk:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": f"You can't remove job {job.id} from analysis"},
            )
        job.analysis = None
        job.save()
        analysis.refresh_from_db()
        # we are possibly changing the status of the analysis
        analysis.set_correct_status(save=True)
        return Response(
            status=status.HTTP_200_OK, data=AnalysisSerializer(instance=analysis).data
        )

    @action(methods=["GET"], url_name="graph", detail=True)
    def tree(self, request, pk):
        obj: Analysis = self.get_object()
        return Response(
            status=status.HTTP_200_OK, data=AnalysisTreeSerializer(instance=obj).data
        )
