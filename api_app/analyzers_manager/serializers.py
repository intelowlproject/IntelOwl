# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from api_app.core.serializers import (
    AbstractReportSerializer,
    PythonConfigSerializer,
    PythonListConfigSerializer,
)

from .models import AnalyzerConfig, AnalyzerReport


class AnalyzerReportSerializer(AbstractReportSerializer):
    """
    AnalyzerReport model's serializer.
    """

    class Meta:
        model = AnalyzerReport
        fields = AbstractReportSerializer.Meta.fields


class AnalyzerConfigSerializer(PythonConfigSerializer):
    class Meta:
        model = AnalyzerConfig
        exclude = ["disabled_in_organizations"]
        list_serializer_class = PythonListConfigSerializer
