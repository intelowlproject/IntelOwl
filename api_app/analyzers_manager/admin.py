from django.contrib import admin

from api_app.analyzers_manager.models import AnalyzerReport


@admin.register(AnalyzerReport)
class AnalyzerReportAdminView(admin.ModelAdmin):
    list_display = (
        "analyzer_name",
        "job",
        "status",
        "start_time",
        "end_time",
    )
    search_fields = ("analyzer_name", "job", "status")
