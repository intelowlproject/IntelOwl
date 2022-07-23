# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import path

from .views import PlaybookListAPI, analyze_multiple_files, analyze_multiple_observables

urlpatterns = [
    path("get_playbook_configs", PlaybookListAPI.as_view()),
    path("playbook/analyze_multiple_files", analyze_multiple_files),
    path("playbook/analyze_multiple_observables", analyze_multiple_observables),
]
