import logging

from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from api_app.analyzables_manager.filters import AnalyzableFilter
from api_app.analyzables_manager.models import Analyzable
from api_app.analyzables_manager.serializers import AnalyzableSerializer

logger = logging.getLogger(__name__)


class AnalyzableViewSet(viewsets.ReadOnlyModelViewSet):

    serializer_class = AnalyzableSerializer
    permission_classes = [IsAuthenticated]
    queryset = Analyzable.objects.all()
    filterset_class = AnalyzableFilter

    def get_queryset(self):
        user = self.request.user
        return super().get_queryset().visible_for_user(user)
