from django.db import models
from django.contrib.postgres import fields as postgres_fields
from cache_memoize import cache_memoize

from intel_owl.secrets import get_secret
from api_app.models import Job


class Analyzer(models.Model):
    analyzer_type = models.CharField(
        max_length=50,
        choices=(
            ("file_analyzer", "file_analyzer"),
            ("observable_analyzer", "observable_analyzer"),
        ),
    )
    disabled = models.BooleanField(default=False, blank=False)
    description = models.TextField()
    python_module = models.CharField(max_length=128, blank=False, null=False)
    config = postgres_fields.JSONField(default=dict, blank=False, null=False)

    @property
    def _cached_secrets(self) -> dict:
        return self.__cached_secrets

    @_cached_secrets.setter
    def _cached_secrets(self, key, val):
        self.__cached_secrets[key] = val

    @cache_memoize(100, args_rewrite=lambda o: o.pk)
    def verify_secrets(self) -> dict:
        verification = {
            "configured:": False,
            "error_message": None,
            "missing_secrets": [],
        }
        for secret in self.secrets.all():
            var = get_secret(secret.env_variable_key)
            if var:
                self._cached_secrets[secret.name] = var
            else:
                verification["missing_secrets"].append(secret.name)

        if len(verification["missing_secrets"]):
            verification["configured"] = True
        else:
            total_secrets = len(self.secrets.all())
            verified_secrets = total_secrets - len(verification["missing_secrets"])
            verification[
                "error_message"
            ] = f'{verification["missing_secrets"]} missing ({verified_secrets} of {total_secrets} satisfied)'  # noqa: E501

        return verification


class AnalyzerReport(models.Model):
    analyzer = models.ForeignKey(
        Analyzer, related_name="reports", on_delete=models.CASCADE
    )
    job = models.ForeignKey(
        Job, related_name="analyzer_reports", on_delete=models.CASCADE
    )

    success = models.BooleanField()
    report = postgres_fields.JSONField(default=dict, blank=False, null=False)
    errors = postgres_fields.ArrayField(
        models.CharField(max_length=512, blank=True, default=list)
    )
    process_time = models.FloatField()
    started_time = models.TimeField()
    started_time_str = models.TextField()


class Secret(models.Model):
    name = models.CharField(max_length=50, blank=False, null=False, unique=True)
    env_variable_key = models.CharField(max_length=50)
    datatype = models.CharField(
        max_length=8,
        choices=(("str", "str"), ("int", "int"), ("bool", "bool"), ("float", "float")),
    )
    required = models.BooleanField(blank=False, default=True)
    default = models.CharField(max_length=50, null=True)
    description = models.TextField()

    analyzer = models.ForeignKey(
        Analyzer, related_name="secrets", on_delete=models.CASCADE
    )
