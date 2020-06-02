from django.contrib import admin
from django.conf.urls import re_path
from django.urls import include, path
from django.contrib.auth import views as auth_views

from api_app.gui import redirect_to_login, query_database, verify_login, logout_request


urlpatterns = [
    re_path("^$", redirect_to_login),
    re_path("admin/", admin.site.urls),
    path("gui/query_database", query_database),
    path(
        "gui/login",
        auth_views.LoginView.as_view(template_name="login.html"),
        {},
        name="login",
    ),
    path("gui/verify_login", verify_login),
    path("gui/logout", logout_request, name="logout"),
    path("api/", include("api_app.urls")),
]
