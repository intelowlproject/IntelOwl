# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from django.http import HttpRequest
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from ..models import Job
from ..permissions import IsObjectOwnerOrSameOrgPermission
from ..views import ModelWithOwnershipViewSet
from .filters import InvestigationFilter
from .models import Investigation
from .serializers import InvestigationSerializer, InvestigationTreeSerializer

logger = logging.getLogger(__name__)


class InvestigationViewSet(ModelWithOwnershipViewSet, ModelViewSet):
    permission_classes = [IsAuthenticated, IsObjectOwnerOrSameOrgPermission]
    serializer_class = InvestigationSerializer
    ordering = ["-start_time"]
    queryset = Investigation.objects.all()
    filterset_class = InvestigationFilter
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
        if "job" not in request.data:
            raise ValidationError({"detail": "You should set the `job` argument in the data"})
        job_pk = request.data.get("job")
        try:
            job = Job.objects.visible_for_user(self.request.user).get(pk=job_pk)
        except Job.DoesNotExist:
            raise NotFound(detail=f"Job {job_pk} does not exist")
        return job

    @action(methods=["POST"], url_name="add_job", detail=True)
    def add_job(self, request, pk):
        investigation: Investigation = self.get_object()
        job: Job = self._get_job(request)
        if not investigation.user_can_edit(job.user):
            raise PermissionDenied("You do not have permissions to add this job to the investigation")
        if not job.is_root():
            raise PermissionDenied("You can add to an investigation only primary jobs")
        if job.investigation is None:
            job.investigation = investigation
            job.save()
            # we are possibly changing the status of the investigation
            job.investigation.set_correct_status(save=True)

            return Response(
                status=status.HTTP_200_OK,
                data=InvestigationSerializer(instance=investigation).data,
            )
        elif job.investigation_id == investigation.id:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": "Job is already part of this investigation"},
            )
        else:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": "Job is already part of different investigation"},
            )

    @action(methods=["POST"], url_name="remove_job", detail=True)
    def remove_job(self, request, pk):
        investigation: Investigation = self.get_object()
        request: HttpRequest
        job: Job = self._get_job(request)
        if not investigation.user_can_edit(job.user):
            raise PermissionDenied("You do not have permissions to edit this investigation with that job")
        if job.investigation_id != investigation.pk:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": f"You can't remove job {job.id} from investigation"},
            )
        job.investigation = None
        job.save()
        investigation.refresh_from_db()
        # we are possibly changing the status of the investigation
        investigation.set_correct_status(save=True)
        response = Response(
            status=status.HTTP_200_OK,
            data=InvestigationSerializer(instance=investigation).data,
        )
        if not investigation.jobs.exists():
            investigation.delete()
        return response

    @action(methods=["GET"], url_name="graph", detail=True)
    def tree(self, request, pk):
        obj: Investigation = self.get_object()
        return Response(
            status=status.HTTP_200_OK,
            data=InvestigationTreeSerializer(instance=obj).data,
        )
