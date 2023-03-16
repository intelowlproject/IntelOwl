import enum


class Color(enum.Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    TERTIARY = "tertiary"
    SUCCESS = "success"
    DANGER = "danger"
    WARNING = "warning"
    INFO = "info"
    DARK = "dark"
    WHITE = "white"
    TRANSPARENT = ""

    def __str__(self):
        return self.value
