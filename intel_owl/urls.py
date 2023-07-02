# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
from django.conf import settings
from django.contrib import admin
from django.shortcuts import render
from django.urls import include, path, re_path

from authentication import views  # temporary solution


def render_reactapp(request):
    return render(request, "index.html")


urlpatterns = [
    path("admin/", admin.site.urls, name="admin"),
    path("api/", include("api_app.urls")),
    path(
        "accounts/github/login/callback/",
        views.GitHubLoginCallbackView.as_view(),
        name="github_callback",
    ),
    path("accounts/", include("allauth.urls")),
    re_path(r"^(?!api|silk)$", render_reactapp),
    re_path(r"^(?!api|silk)(?:.*)/?$", render_reactapp),
]
if settings.STAGE_STAGING or settings.STAGE_LOCAL:
    urlpatterns.append(path("silk/", include("silk.urls"), name="silk"))
