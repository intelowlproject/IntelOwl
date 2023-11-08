from django.utils.duration import _get_duration_components
from rest_framework.fields import DurationField


def duration_string(duration):
    """Version of str(timedelta) which is not English specific."""
    days, hours, minutes, seconds, microseconds = _get_duration_components(duration)

    string = "{}:{:02d}:{:02d}:{:02d}".format(days, hours, minutes, seconds)
    if microseconds:
        string += ".{:06d}".format(microseconds)

    return string


class DayDurationField(DurationField):
    @staticmethod
    def to_representation(value):
        return duration_string(value)
