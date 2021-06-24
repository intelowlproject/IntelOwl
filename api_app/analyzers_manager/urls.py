from django.urls import path

from .views import AnalyzerListAPI

urlpatterns = [
    path("get_analyzer_configs", AnalyzerListAPI.as_view()),
]
