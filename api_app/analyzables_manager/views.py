import logging

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from api_app.analyzables_manager.models import Analyzable
from api_app.analyzables_manager.serializers import AnalyzableSerializer

logger = logging.getLogger(__name__)


class AnalyzableViewSet(viewsets.ReadOnlyModelViewSet):

    serializer_class = AnalyzableSerializer
    permission_classes = [IsAuthenticated]
    queryset = Analyzable.objects.all()

    def get_queryset(self):
        user = self.request.user
        return super().get_queryset().visible_for_user(user)

    @action(detail=False, methods=["post"])
    def get_analyzables(self, request):
        logger.info(f"received get_analyzables from user {request.user}")
        logger.debug(f"{request.data=}")

        analyzables = []
        for name in request.data:
            try:
                analyzable = Analyzable.objects.get(name=name)
                analyzables.append(AnalyzableSerializer(analyzable).data)
            except Analyzable.DoesNotExist:
                analyzable_nf = {
                    "name": name,
                    "tags": ["not found"],
                }
                analyzables.append(analyzable_nf)
        return Response(analyzables, status=status.HTTP_200_OK)
