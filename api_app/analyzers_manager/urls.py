from django.urls import include, path
from rest_framework import routers
from views import AnalyzerViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"analyzer", AnalyzerViewSet)

urlpatterns = [
    # Viewsets
    path(r"", include(router.urls))
]
