# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from drf_spectacular.utils import extend_schema as add_docs
from drf_spectacular.utils import inline_serializer

from api_app.core.views import PluginActionViewSet, PluginHealthCheckAPI
from certego_saas.ext.views import APIView

from rest_framework import serializers as rfs
from rest_framework import status
from rest_framework.response import Response


from . import controller as playbooks_controller
from .models import PlaybookReport
from .serializers import PlaybookConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "PlaybookListAPI",
    "PlaybookActionViewSet"
]

class PlaybookListAPI(APIView):
    serializer_class = PlaybookConfigSerializer

    @add_docs(
        description="Get and parse the `connector_config.json` file,",
        parameters=[],
        responses={
            200: PlaybookConfigSerializer,
            500: inline_serializer(
                name="GetPlaybookConfigsFailedResponse",
                fields={"error": rfs.StringRelatedField()},
            ),
        },
    )
    def get(self, request, *args, **kwargs):
        try:
            pc = self.serializer_class.read_and_verify_config()
            return Response(pc, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception(
                f"get_playbook_configs requester:{str(request.user)} error:{e}."
            )
            return Response(
                {"error": "error in get_playbook_configs. Check logs."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PlaybookActionViewSet(PluginActionViewSet):
    queryset = PlaybookReport.objects.all()

    @property
    def report_model(self):
        return PlaybookReport
    
    def perform_retry(self, report: PlaybookReport):
        playbooks_to_execute, runtime_configuration = super().perform_retry(report)
        playbooks_controller.start_playbooks(
            report.job.id,
            playbooks_to_execute,
            runtime_configuration,
        )

