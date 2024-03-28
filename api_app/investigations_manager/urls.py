from django.urls import include, path
from rest_framework import routers

from .views import InvestigationViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"investigation", InvestigationViewSet, basename="investigation")

urlpatterns = [
    path(r"", include(router.urls)),
]
