from django.db.models import IntegerChoices


class DecayProgressionEnum(IntegerChoices):
    LINEAR = 0  # 10 -> N days -> 9 -> N days -> 8
    INVERSE_EXPONENTIAL = 1  # 10 -> N days -> 9 -> N*N days -> 8
    FIXED = 2  # 10 -> N days -> 10 -> N days -> 10
