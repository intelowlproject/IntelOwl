from django.urls import include, path
from rest_framework import routers

from .views import AnalysisViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"analysis", AnalysisViewSet, basename="analysis")

urlpatterns = [
    path(r"", include(router.urls)),
]
