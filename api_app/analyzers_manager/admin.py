from django.contrib import admin

from guardian.admin import GuardedModelAdmin

from api_app.analyzers_manager.models import Analyzer, AnalyzerReport, Secret


class AnalyzerAdminView(GuardedModelAdmin):
    list_display = (
        "name",
        "analyzer_type",
        "disabled",
        "description",
        "python_module",
        "config",
    )
    search_fields = ("name", "analyzer_type", "description", "disabled")


class AnalyzerReportAdminView(GuardedModelAdmin):
    list_display = (
        "analyzer",
        "job",
        "status",
        "report",
        "errors",
        "start_time",
        "end_time",
    )
    search_fields = ("analyzer", "job", "status")


class SecretAdminView(GuardedModelAdmin):
    list_display = (
        "name",
        "env_variable_key",
        "datatype",
        "required",
        "default",
        "description",
    )
    search_fields = ("name", "description")


admin.site.register(Analyzer, AnalyzerAdminView)
admin.site.register(AnalyzerReport, AnalyzerReportAdminView)
admin.site.register(Secret, SecretAdminView)
