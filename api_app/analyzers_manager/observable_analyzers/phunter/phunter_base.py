import phonenumbers
import requests
from bs4 import BeautifulSoup
from phonenumbers import carrier


class PhunterBase:
    def __init__(self):
        pass

    @staticmethod
    def phunt(phone_number: str) -> dict:

        # General Information

        parsed = phonenumbers.parse(phone_number)

        possible = phonenumbers.is_possible_number(parsed)

        valid = phonenumbers.is_valid_number(parsed)

        operator = carrier.name_for_number(parsed, "en")
        if operator == "":
            operator = "Not found"

        line = phonenumbers.number_type(parsed)
        if line == phonenumbers.PhoneNumberType.FIXED_LINE:
            ligne = "Fixed"
        elif line == phonenumbers.PhoneNumberType.MOBILE:
            ligne = "Mobile"
        else:
            ligne = "Not found"

        # Free Lookup

        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0"

        free_lookup_url = f"https://free-lookup.net/{phone_number.replace('+', '')}"

        r = requests.get(free_lookup_url, headers={"user-agent": user_agent})

        html_body = BeautifulSoup(r.text, "html.parser")
        list_info = html_body.findChild("ul", class_="report-summary__list").findAll(
            "div"
        )

        info_dict = {
            k.text.strip(): info.text.strip() if info.text.strip() else "Not found"
            for _, (k, info) in enumerate(zip(list_info[::2], list_info[1::2]))
        }

        # Spamcalls

        spammer = False

        spamcalls_url = f"https://spamcalls.net/en/number/{phone_number}"

        r = requests.get(spamcalls_url, headers={"user-agent": user_agent})

        spammer = r.status_code == 200

        result = {
            "Phone Number": phone_number,
            "Possible": possible,
            "Valid": valid,
            "Operator": operator,
            "Line Type": ligne,
            "Free Lookup": info_dict,
            "Spamcalls": spammer,
        }

        return result
