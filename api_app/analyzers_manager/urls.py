from django.urls import include, path
from rest_framework import routers
from views import AnalyzerReportViewSet, AnalyzerConfigViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"analyzer_report", AnalyzerReportViewSet)
router.register(r"analyzer_config", AnalyzerConfigViewSet)

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls))
]
