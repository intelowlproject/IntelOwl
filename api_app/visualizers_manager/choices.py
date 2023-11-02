from django.db import models


class Position(models.TextChoices):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
