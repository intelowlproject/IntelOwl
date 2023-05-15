# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import enum


class VisualizableSize(enum.Enum):
    S_1 = "1"
    S_2 = "2"
    S_3 = "3"
    S_4 = "4"
    S_5 = "5"
    S_6 = "6"
    S_7 = "7"
    S_8 = "8"
    S_9 = "9"
    S_10 = "10"
    S_11 = "11"
    S_ALL = "12"
    S_AUTO = "auto"

    def __str__(self):
        return self.value


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
    ALARM = "alarm"
    MAGNIFYING_GLASS = "magnifyingGlass"
    CREDIT_CARD = "creditCard"
    EMAIL = "email"
    PHISHING = "hook"
    FILTER = "filter"
    INCOGNITO = "incognito"
    INBOX = "inbox"
    CLOUD_UPLOAD = "cloudUpload"
    CLOUD_SYNC = "cloudSync"
    LIGHTHOUSE_ON = "lighthouseOn"
    CONTROLLER = "controller"
    EXIT = "exit"
    CONNECTION = "connection"
    LOCKER = "locker"
    # external services
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


class VisualizableAlignment(enum.Enum):
    START = "start"
    CENTER = "center"
    END = "end"
    BETWEEN = "between"
    AROUND = "around"

    def __str__(self):
        return self.value

    def __bool__(self):
        return True
