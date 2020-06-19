from django.contrib import admin
from django.views.generic.base import RedirectView
from django.urls import include, path

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="admin", permanent=False)),
    path("admin/", admin.site.urls, name="admin"),
    path("api/", include("api_app.urls")),
]
