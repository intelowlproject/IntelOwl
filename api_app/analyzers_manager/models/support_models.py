from logging import getLogger

from django.db import models
from django.utils.timezone import now

logger = getLogger(__name__)


class SupportModel(models.Model):
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    @classmethod
    def generate(cls, data):
        records = []
        for i, record in enumerate(data):
            records.append(cls(**record))
            if i % 10000 == 0 and i != 0 and records:
                cls.objects.bulk_create(records, ignore_conflicts=True)
                records = []
        if records:
            cls.objects.bulk_create(records, ignore_conflicts=True)

    @classmethod
    def reset(cls):
        cls.objects.all().delete()


class FireHolRecord(SupportModel):
    version = models.IntegerField(default=1)
    file_date = models.DateTimeField()
    source = models.CharField(max_length=300)
    ip_start = models.GenericIPAddressField()
    ip_end = models.GenericIPAddressField()
    category = models.CharField(max_length=300)

    class Meta:
        unique_together = ("source", "ip_start", "ip_end", "category")

    @classmethod
    def generate(cls, data):
        records = []
        for i, record in enumerate(data):
            logger.debug(f"Record is: {record}")
            records.append(cls(**record))
            if i % 10000 == 0 and i != 0 and records:
                cls.objects.bulk_create(
                    records,
                    update_conflicts=True,
                    update_fields=["file_date"],
                    unique_fields=["source", "ip_start", "ip_end", "category"],
                )
                records = []
        if records:
            cls.objects.bulk_create(
                records,
                update_conflicts=True,
                update_fields=["file_date"],
                unique_fields=["source", "ip_start", "ip_end", "category"],
            )


class TorExitAddress(SupportModel):
    ip = models.GenericIPAddressField(unique=True)


class TrancoRecord(SupportModel):
    version = models.IntegerField(default=0)
    rank = models.IntegerField()
    domain = models.CharField(max_length=512)
    retrieved_date = models.DateTimeField(default=now)

    class Meta:
        unique_together = ("rank", "domain", "retrieved_date")
