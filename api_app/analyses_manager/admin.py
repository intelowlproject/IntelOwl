from django.contrib import admin

from api_app.admin import CustomAdminView
from api_app.analyses_manager.models import Analysis


@admin.register(Analysis)
class AnalysisAdminView(CustomAdminView):
    list_display = ["name", "start_time", "status", "owner", "get_jobs", "total_jobs"]
    list_filter = ["owner", "status"]
    search_fields = ["name"]

    @admin.display(description="Total Jobs")
    def total_jobs(self, instance: Analysis):
        from api_app.models import Job

        string = ""
        for i, job in enumerate(instance.jobs.all()):
            job: Job
            tree = job.get_tree(job)
            jobs_repr = " ".join(map(str, tree.values_list("pk", flat=True)))
            string += f"Branch {i+1}: jobs -> {jobs_repr}; "
        return string

    @admin.display(description="Jobs at first level")
    def get_jobs(self, instance: Analysis):
        return list(instance.jobs.all().values_list("pk", flat=True))
