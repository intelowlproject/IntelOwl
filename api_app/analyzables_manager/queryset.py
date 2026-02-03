import logging

from django.db.models import QuerySet

logger = logging.getLogger(__name__)


class AnalyzableQuerySet(QuerySet):
    def visible_for_user(self, user):
        from api_app.models import Job
        from api_app.user_events_manager.models import UserAnalyzableEvent

        analyzables_job = (
            Job.objects.visible_for_user(user)
            .values("analyzable")
            .distinct()
            .values_list("analyzable__pk", flat=True)
        )
        analyzables_ue = (
            UserAnalyzableEvent.objects.visible_for_user(user)
            .values("analyzable")
            .distinct()
            .values_list("analyzable__pk", flat=True)
        )
        return self.filter(pk__in=analyzables_job) | self.filter(pk__in=analyzables_ue)

    def create(self, *args, **kwargs):
        obj = self.model(**kwargs)
        self._for_write = True
        try:
            obj.full_clean()
        except Exception as e:
            logger.error(f"Already exists obj {obj.md5}")
            raise e
        obj.save(force_insert=True, using=self.db)
        return obj
