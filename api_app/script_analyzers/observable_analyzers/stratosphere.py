import os
import logging
import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import settings
from datetime import datetime, date

logger = logging.getLogger(__name__)

db_name0 = "stratos_ip_blacklist_last24hrs.csv"
db_name1 = "stratos_ip_blacklist_new_attacker.csv"
db_name2 = "stratos_ip_blacklist_repeated_attacker.csv"

db_loc0 = f"{settings.MEDIA_ROOT}/{db_name0}"
db_loc1 = f"{settings.MEDIA_ROOT}/{db_name1}"
db_loc2 = f"{settings.MEDIA_ROOT}/{db_name2}"


class Stratos(classes.ObservableAnalyzer):
    def check_in_list(self, dataset_loc, ip):
        # Checks the IP in a list(S.No,IP,Rating).
        with open(dataset_loc, "r") as f:
            db = f.read()

        db_list = db.split("\n")

        for ip_tuple in enumerate(db_list):
            if ip_tuple[0] >= 2:
                if ip in ip_tuple[1]:
                    ip_rating = ((ip_tuple[1].split(","))[2]).strip()
                    return ip_rating
        return ""

    def run(self):
        ip = self.observable_name
        result = {
            "last24hrs_rating": "",
            "new_attacker_rating": "",
            "repeated_attacker_rating": "",
        }

        self.check_dataset_status()

        # Checks the IP in last24hrs attacker list.
        result["last24hrs_rating"] = self.check_in_list(db_loc0, ip)
        # Checks the IP in new attacker list.
        result["new_attacker_rating"] = self.check_in_list(db_loc1, ip)
        # Checks the IP in repeated attacker list.
        result["repeated_attacker_rating"] = self.check_in_list(db_loc2, ip)

        return result

    def download_dataset(self, url, db_loc):
        # Dataset website certificates are not correctly configured.
        p = requests.get(url, verify=False)
        p.raise_for_status()

        with open(db_loc, "w") as f:
            f.write(p.content.decode())

    def updater(self):
        try:
            logger.info("starting download of dataset from stratosphere")

            base_url = "https://mcfp.felk.cvut.cz"
            mid_url = "/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/"
            url0 = base_url + mid_url + "AIP_blacklist_for_IPs_seen_last_24_hours.csv"
            priority_url = "AIP_historical_blacklist_prioritized_by_"
            url1 = base_url + mid_url + priority_url + "newest_attackers.csv"
            url2 = base_url + mid_url + priority_url + "repeated_attackers.csv"

            self.download_dataset(url0, db_loc0)
            self.download_dataset(url1, db_loc1)
            self.download_dataset(url2, db_loc2)

            if not os.path.exists(db_loc0 or db_loc1 or db_loc2):
                raise AnalyzerRunException("failed extraction of stratosphere dataset")

            logger.info("ended download of dataset from stratosphere")

        except Exception as e:
            logger.debug("Traceback %s", exc_info=True)
            logger.exception(e)

        db_location = [db_loc0, db_loc1, db_loc2]

        return db_location

    def check_dataset_status(self):
        if not os.path.isfile(db_loc0 and db_loc1 and db_loc2):
            self.updater()
        today = date.today()

        timestamp = os.path.getctime(db_loc0)
        dt_object = datetime.fromtimestamp(timestamp)

        if (
            dt_object.hour > 3
            and today.day == dt_object.day
            and today.month == dt_object.month
            and today.year == dt_object.year
        ):
            logger.info("Dataset is up to date")
        else:
            os.remove(db_loc0)
            os.remove(db_loc1)
            os.remove(db_loc2)
            self.updater()
