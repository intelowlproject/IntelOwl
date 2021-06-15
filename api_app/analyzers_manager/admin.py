from django.contrib import admin

from api_app.analyzers_manager.models import Analyzer, AnalyzerReport, Secret


@admin.register(Analyzer)
class AnalyzerAdminView(admin.ModelAdmin):
    list_display = (
        "name",
        "analyzer_type",
        "disabled",
        "description",
        "python_module",
        "config",
    )
    search_fields = ("name", "analyzer_type", "description", "disabled")


@admin.register(AnalyzerReport)
class AnalyzerReportAdminView(admin.ModelAdmin):
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


@admin.register(Secret)
class SecretAdminView(admin.ModelAdmin):
    list_display = (
        "name",
        "env_variable_key",
        "datatype",
        "required",
        "default",
        "description",
    )
    search_fields = ("name", "description")
