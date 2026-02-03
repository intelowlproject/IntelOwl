from django.core.validators import RegexValidator

pivot_regex_validator = RegexValidator(r"^\w+(\.\w+)*$", message="Object should be a python path")
