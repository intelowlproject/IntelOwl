from django.contrib import admin

from api_app.user_events_manager.models import (
    UserAnalyzableEvent,
    UserDomainWildCardEvent,
    UserIPWildCardEvent,
)


@admin.register(UserAnalyzableEvent)
class UserAnalyzableEventAdmin(admin.ModelAdmin):
    list_display = [
        "pk",
        "user",
        "analyzable",
        "date",
        "data_model",
        "decay_progression",
        "decay_timedelta_days",
        "next_decay",
    ]
    list_filter = ["user", "date", "next_decay"]
    ordering = ["date"]
    search_fields = ["analyzable"]


@admin.register(UserDomainWildCardEvent)
class UserDomainWildCardEventAdmin(admin.ModelAdmin):
    list_display = [
        "pk",
        "user",
        "query",
        "get_analyzables",
        "date",
        "data_model",
        "decay_progression",
        "decay_timedelta_days",
        "next_decay",
    ]
    list_filter = ["user", "date", "next_decay"]
    ordering = ["date"]
    search_fields = ["analyzables"]

    @admin.display(description="Analyzables")
    def get_analyzables(self, instance):
        return [analyzable.name for analyzable in instance.analyzables.all()]


@admin.register(UserIPWildCardEvent)
class UserIPWildCardEventAdmin(admin.ModelAdmin):
    list_display = [
        "pk",
        "user",
        "start_ip",
        "end_ip",
        "get_analyzables",
        "date",
        "data_model",
        "decay_progression",
        "decay_timedelta_days",
        "next_decay",
    ]
    list_filter = ["user", "date", "next_decay"]
    ordering = ["date"]
    search_fields = ["analyzables"]

    @admin.display(description="Analyzables")
    def get_analyzables(self, instance):
        return [analyzable.name for analyzable in instance.analyzables.all()]
