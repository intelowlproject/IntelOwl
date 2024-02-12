# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from ..views import PythonConfigViewSet, PythonReportActionViewSet
from .filters import AnalyzerConfigFilter
from .models import AnalyzerReport
from .serializers import AnalyzerConfigSerializer

logger = logging.getLogger(__name__)


__all__ = [
    "AnalyzerConfigViewSet",
    "AnalyzerActionViewSet",
]


class AnalyzerConfigViewSet(PythonConfigViewSet):
    serializer_class = AnalyzerConfigSerializer
    filterset_class = AnalyzerConfigFilter


class AnalyzerActionViewSet(PythonReportActionViewSet):
    @classmethod
    @property
    def report_model(cls):
        return AnalyzerReport
