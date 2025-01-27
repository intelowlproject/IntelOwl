from django.db.models import QuerySet


class AnalyzableQuerySet(QuerySet):

    def visible_for_user(self, user):
        from api_app.models import Job

        jobs = (
            Job.objects.visible_for_user(user)
            .values("analyzable")
            .distinct()
            .values_list("pk", flat=True)
        )
        return self.filter(pk__in=jobs)

    def create(self, *args, **kwargs):
        obj = self.model(**kwargs)
        self._for_write = True
        obj.full_clean()
        obj.save(force_insert=True, using=self.db)
        return obj
