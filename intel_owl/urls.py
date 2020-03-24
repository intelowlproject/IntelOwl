from django.contrib import admin
from django.urls import re_path
from django.contrib.auth import views as auth_views

from api_app.views import *

urlpatterns = [
    re_path('^$', redirect_to_login),
    re_path('admin/', admin.site.urls),
    re_path(r'^api/ask_analysis_availability', ask_analysis_availability),
    re_path(r'^api/send_analysis_request$', send_analysis_request),
    re_path(r'^api/ask_analysis_result', ask_analysis_result),
    re_path(r'^api/get_analyzer_configs', get_analyzer_configs),
    re_path(r'^gui/query_database$', query_database),
    re_path(r'^gui/query_database/(?P<job_id>\d+)', query_database_json),
    re_path(r'^gui/login$', auth_views.LoginView.as_view(template_name="login.html"), {}, name='login'),
    re_path(r'^gui/verify_login$', verify_login),
    re_path(r'^gui/logout$', logout_request, name='logout')
]
