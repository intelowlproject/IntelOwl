# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin
from django.views.generic.base import RedirectView
from django.urls import include, path

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="admin", permanent=False)),
    path("admin/", admin.site.urls, name="admin"),
    path("api/", include("api_app.urls")),
]
