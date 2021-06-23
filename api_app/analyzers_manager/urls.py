from django.urls import include, path
from rest_framework import routers
from views import AnalyzerReportViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"analyzer_report", AnalyzerReportViewSet)

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls))
]
