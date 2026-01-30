from django.core.exceptions import ValidationError
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api_app.engines_manager.models import EngineConfig
from api_app.mixins import PaginationMixin
from api_app.permissions import IsObjectOwnerOrSameOrgPermission


class EngineViewSet(PaginationMixin, viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated, IsObjectOwnerOrSameOrgPermission]
    queryset = EngineConfig.objects.all()

    @action(
        methods=["POST"],
        detail=False,
    )
    def run(self, request):
        from api_app.models import Job

        if "job" not in request.data:
            raise ValidationError({"detail": "You should set the `job` argument in the data"})
        job_pk = request.data["job"]
        job = Job.objects.get(pk=job_pk)
        EngineConfig.objects.first().run(job)
        return Response({"success": True}, status=status.HTTP_200_OK)
