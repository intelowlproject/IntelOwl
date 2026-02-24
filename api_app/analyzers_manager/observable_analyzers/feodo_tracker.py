# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import os
from typing import Tuple

import requests
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.decorators import classproperty
from api_app.mixins import AbuseCHMixin
from api_app.models import PluginConfig

logger = logging.getLogger(__name__)


class Feodo_Tracker(AbuseCHMixin, classes.ObservableAnalyzer):
    """
    Feodo Tracker offers various blocklists,
    helping network owners to protect their
    users from Dridex and Emotet/Heodo.
    """

    use_recommended_url: bool
    update_on_run: bool = True

    @classproperty
    def recommend_locations(cls) -> Tuple[str, str]:
        db_name = "feodotracker_abuse_ipblocklist.json"
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
        return f"{settings.MEDIA_ROOT}/{db_name}", url

    @classproperty
    def default_locations(cls) -> Tuple[str, str]:
        db_name = "feodotracker_abuse_ipblocklist_recommended.json"
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        return f"{settings.MEDIA_ROOT}/{db_name}", url

    def run(self):
        result = {"found": False}
        db_location, _ = (
            self.recommend_locations
            if self.use_recommended_url
            else self.default_locations
        )
        if self.update_on_run or not os.path.exists(db_location) and not self.update():
            raise AnalyzerRunException("Unable to update database")
        try:
            with open(db_location, "r", encoding="utf-8") as f:
                db = json.load(f)
            # db is a list of dictionaries
            for ip in db:
                if ip["ip_address"] == self.observable_name:
                    result["found"] = True
                    break
        except json.JSONDecodeError as e:
            raise AnalyzerRunException(f"Decode JSON in run: {e}")
        except FileNotFoundError as e:
            raise AnalyzerRunException(f"File not found in run: {e}")
        except KeyError as e:
            raise AnalyzerRunException(f"Key error in run: {e}")
        return result

    # this is necessary because during the "update()" flow the config()
    # method is not called and the attributes would not be accessible by "cls"
    @classmethod
    def get_service_auth_headers(cls) -> {}:
        for plugin in PluginConfig.objects.filter(
            parameter__python_module=cls.python_module,
            parameter__is_secret=True,
            parameter__name="service_api_key",
        ):
            if plugin.value:
                logger.debug("Found auth key for feodo tracker update")
                return {"Auth-Key": plugin.value}

        logger.debug("Not found auth key for feodo tracker update")
        return {}

    @classmethod
    def update(cls) -> bool:
        """
        Simply update the database
        """
        for db_location, db_url in [cls.default_locations, cls.recommend_locations]:
            logger.info(f"starting download of db from {db_url}")

            try:
                r = requests.get(db_url, headers=cls.get_service_auth_headers())
                r.raise_for_status()
            except requests.RequestException:
                return False
            with open(db_location, "w", encoding="utf-8") as f:
                try:
                    json.dump(r.json(), f)
                except json.JSONDecodeError:
                    return False
                logger.info(f"ended download of db from Feodo Tracker at {db_location}")
        return True
