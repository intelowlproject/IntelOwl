from django.db.models import IntegerChoices


class DecayProgressionEnum(IntegerChoices):
    LINEAR = 0 # A -> N days -> B -> N days -> C
    INVERSE_EXPONENTIAL = 1 # A -> N days -> B -> N*N days -> C
    FIXED = 2 # A -> N days -> A -> N days -> C
