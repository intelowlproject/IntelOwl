# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import enum


class VisualizableColor(enum.Enum):
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

    def __bool__(self):
        if self is self.TRANSPARENT:
            return False
        return True


class VisualizableIcon(enum.Enum):
    INFO = "info"
    LIKE = "like"
    DISLIKE = "dislike"
    HEART = "heart"
    MALWARE = "malware"
    WARNING = "warning"
    SHIELD = "shield"
    FIRE = "fire"
    OTX = "otx"
    GITHUB = "github"
    VIRUSTotal = "virusTotal"
    TWITTER = "twitter"
    QUOKKA = "quokka"
    HYBRIDAnalysis = "hybridAnalysis"
    URLHAUS = "urlhaus"
    GOOGLE = "google"
    CLOUDFLARE = "cloudflare"
    QUAD_9 = "quad9"

    EMPTY = ""

    def __bool__(self):
        if self is self.EMPTY:
            return False
        return True
