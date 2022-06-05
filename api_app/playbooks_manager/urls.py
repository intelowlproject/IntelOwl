# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import include, path
from rest_framework import routers

from .views import PlaybookListAPI, analyze_file, analyze_observable

urlpatterns = [
    path("get_playbook_configs", PlaybookListAPI.as_view()),
    path("playbook/analyze_file", analyze_file),
    path("playbook/analyze_observable", analyze_observable),
]