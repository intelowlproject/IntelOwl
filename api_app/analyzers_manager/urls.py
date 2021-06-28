# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import path

from .views import AnalyzerListAPI

urlpatterns = [
    path("get_analyzer_configs", AnalyzerListAPI.as_view()),
]
