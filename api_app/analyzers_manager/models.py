from django.db import models
from django.contrib.postgres import fields as postgres_fields
from cache_memoize import cache_memoize

from intel_owl.secrets import get_secret


class Analyzer(models.Model):
    TYPE_CHOICES = (
        ("file_analyzer", "file_analyzer"),
        ("observable_analyzer", "observable_analyzer"),
    )
    QUEUE_CHOICES = (
        ("default", "default"),
        ("long", "long"),
        ("local", "local"),
    )
    HASH_CHOICES = (("md5", "md5"), ("sha256", "sha256"))

    name = models.CharField(max_length=128, blank=False, unique=True)
    analyzer_type = models.CharField(
        max_length=50,
        choices=TYPE_CHOICES,
        blank=False,
    )
    disabled = models.BooleanField(default=False)
    description = models.TextField(blank=True)
    python_module = models.CharField(max_length=128, blank=False)
    supported_filetypes = postgres_fields.ArrayField(
        models.CharField(default=list, max_length=50, blank=True)
    )
    not_supported_filetypes = postgres_fields.ArrayField(
        models.CharField(default=list, max_length=50, blank=True)
    )
    run_hash = models.BooleanField(default=False)
    run_hash_type = models.CharField(
        max_length=50,
        blank=True,
        choices=HASH_CHOICES,
        default="md5",
    )
    observable_supported = postgres_fields.ArrayField(
        models.CharField(default=list, max_length=50, blank=True)
    )
    leaks_info = models.BooleanField(default=False)
    external_service = models.BooleanField(default=False)
    queue = models.CharField(max_length=50, choices=QUEUE_CHOICES, default="default")
    soft_time_limit = models.PositiveIntegerField(default=300)
    additional_config_params = models.JSONField(default=dict, blank=True)

    def __str__(self):
        return self.name

    @property
    def _cached_secrets(self) -> dict:
        return self.__cached_secrets

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
                self.__cached_secrets[secret.name] = var
            else:
                verification["missing_secrets"].append(secret.name)

        if len(verification["missing_secrets"]) == 0:
            verification["configured"] = True
        else:
            total_secrets = self.secrets.all().count()
            verified_secrets = total_secrets - len(verification["missing_secrets"])
            verification[
                "error_message"
            ] = f'{verification["missing_secrets"]} missing ({verified_secrets} of {total_secrets} satisfied)'  # noqa: E501

        return verification


class AnalyzerReport(models.Model):
    STATUS_CHOICES = (
        ("pending", "pending"),
        ("running", "running"),
        ("failed", "failed"),
        ("success", "success"),
    )
    analyzer = models.ForeignKey(
        Analyzer, related_name="reports", on_delete=models.CASCADE
    )
    job = models.ForeignKey(
        "api_app.Job", related_name="analyzer_reports", on_delete=models.CASCADE
    )

    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
        blank=False,
    )
    report = models.JSONField(default=dict, blank=False)
    errors = postgres_fields.ArrayField(
        models.CharField(max_length=512, blank=True, default=list)
    )
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()


class Secret(models.Model):
    CHOICES = (("str", "str"), ("int", "int"), ("bool", "bool"), ("float", "float"))

    name = models.CharField(max_length=50, blank=False, unique=True)
    env_variable_key = models.CharField(max_length=50)
    datatype = models.CharField(
        max_length=8,
        choices=CHOICES,
    )
    required = models.BooleanField(default=True)
    default = models.CharField(max_length=50, blank=True)
    description = models.TextField()

    analyzer = models.ForeignKey(
        Analyzer, related_name="secrets", on_delete=models.CASCADE
    )

    def __str__(self):
        return self.name
