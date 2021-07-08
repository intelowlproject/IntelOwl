# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.urls import path

from .views import ConnectorListAPI

urlpatterns = [
    path("get_connector_configs", ConnectorListAPI.as_view()),
]
