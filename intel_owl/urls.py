# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path, re_path


def render_reactapp(request):
    return render(request, "index.html")


urlpatterns = [
    path("admin/", admin.site.urls, name="admin"),
    path("api/", include("api_app.urls")),
    re_path(r"^(?!api)$", render_reactapp),
    re_path(r"^(?!api)(?:.*)/?$", render_reactapp),
]
