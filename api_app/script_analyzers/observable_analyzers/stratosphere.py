import os
import logging
import traceback
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
    def run(self):
        ip = self.observable_name
        result = {
            "last24hrs": False,
            "last24hrs_rating": "_",
            "new_attacker": False,
            "new_attacker_rating": "_",
            "repeated_attacker": False,
            "repeated_attacker_rating": "_",
        }

        self.check_dataset_status()

        with open(db_loc0, "r") as f:
            db = f.read()
        db_list = db.split("\n")
        count = 0
        for ip_tuple in db_list:
            if count < 2:
                count += 1
                continue
            else:
                if ip in ip_tuple:
                    ip_rating = ((ip_tuple.split(","))[2]).strip()
                    result["last24hrs"] = True
                    result["last24hrs_rating"] = ip_rating

        with open(db_loc1, "r") as f:
            db = f.read()
        db_list = db.split("\n")
        count = 0
        for ip_tuple in db_list:
            if count < 2:
                count += 1
                continue
            else:
                if ip in ip_tuple:
                    ip_rating = ((ip_tuple.split(","))[2]).strip()
                    result["new_attacker"] = True
                    result["new_attacker_rating"] = ip_rating

        with open(db_loc2, "r") as f:
            db = f.read()
        db_list = db.split("\n")
        count = 0
        for ip_tuple in db_list:
            if count < 2:
                count += 1
                continue
            else:
                if ip in ip_tuple:
                    ip_rating = ((ip_tuple.split(","))[2]).strip()
                    result["repeated_attacker"] = True
                    result["repeated_attacker_rating"] = ip_rating

        return result

    def updater(self):
        try:
            logger.info("starting download of dataset from stratosphere")

            base_url = "https://mcfp.felk.cvut.cz"
            mid_url = "/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/"
            url0 = base_url + mid_url + "AIP_blacklist_for_IPs_seen_last_24_hours.csv"
            priority_url = "AIP_historical_blacklist_prioritized_by_"
            url1 = base_url + mid_url + priority_url + "newest_attackers.csv"
            url2 = base_url + mid_url + priority_url + "repeated_attackers.csv"

            p = requests.get(url0, verify=False)
            p.raise_for_status()

            q = requests.get(url1, verify=False)
            q.raise_for_status()

            r = requests.get(url2, verify=False)
            r.raise_for_status()

            with open(db_loc0, "w") as f:
                f.write(p.content.decode())

            with open(db_loc1, "w") as f:
                f.write(q.content.decode())

            with open(db_loc2, "w") as f:
                f.write(r.content.decode())

            if not os.path.exists(db_loc0 or db_loc1 or db_loc2):
                raise AnalyzerRunException("failed extraction of stratosphere dataset")

            logger.info("ended download of dataset from stratosphere")

        except Exception as e:
            traceback.print_exc()
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
            today.day == dt_object.day
            and today.month == dt_object.month
            and today.year == dt_object.year
        ):
            logger.info("Dataset is up to date")
        else:
            os.remove(db_loc0)
            os.remove(db_loc1)
            os.remove(db_loc2)
            self.updater()
