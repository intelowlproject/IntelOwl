from django.db import models


class CleanOnCreateQuerySet(models.QuerySet):
    def create(self, **kwargs):
        obj = self.model(**kwargs)
        obj: models.Model
        obj.full_clean()
        self._for_write = True
        obj.save(force_insert=True, using=self.db)
        return obj
