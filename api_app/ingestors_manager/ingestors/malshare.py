import logging
from typing import Any, Iterable

from api_app.ingestors_manager.classes import Ingestor

# from tests.mock_utils import MockUpResponse, if_mock_connections

logger = logging.getLogger(__name__)


class Malshare(Ingestor):

    url: str
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> Iterable[Any]:
        print("malshare run")
        # self._api_key_name="16fd330a437706c7d5e52b5d5688125fdb6ab04df10547e58c8918c902db815c"
        # req_url = (
        #     f"https://malshare.com//api.php?api_key={self._api_key_name}&action=getlist"
        # )
        # result = requests.get(req_url)
        # result.raise_for_status()
        # content = result.json()
        # print(content)
        # if not isinstance(content, list):
        #     raise IngestorRunException(f"Content {content} not expected")

        # limit = min(len(content["iocs"]), self.limit)
        # for elem in content["iocs"][0:10]:
        #     value = elem.get("sha256")
        #     print(value)
        # try:
        #     ipaddress.ip_address(value)
        #     yield value
        # except ValueError:
        #     pass

    # @classmethod
    # def _monkeypatch(cls):
    #     patches = [
    #         if_mock_connections(
    #             patch(
    #                 "requests.get",
    #                 return_value=MockUpResponse(
    #                     {
    #                        [
    #                         {
    #                             "md5": "56cb253271d0bc47e2869d351ebd2551",
    #                             "sha1": "8620e2d371740651fb2a111cbaf3ba1632b61b61",
    #                             "sha256": "6cf10ac2e7b6bd7ff09e237322a89b1259da78bd54c20fe11339092fa921cf45"
    #                         },
    #                         {
    #                             "md5": "56cb33e74796abcaa39783e8e873e351",
    #                             "sha1": "0d72b496d104eb71ecb9d2107b99425e3eccf566",
    #                             "sha256": "f85f9bd1a1cb68514876c2b13b8643715d551e055c7cb26f764a42abaac41067"
    #                         },
    #                         {
    #                             "md5": "56cb78ab63ac800ef1e900a2ca855e90",
    #                             "sha1": "cbbbf4c8608a0722a8490b352364a030211dfdbd",
    #                             "sha256": "c26841fc297fadba690e4ae3be2f9f1fbef0766b46a828d7f12814dddcbd5478"
    #                         }
    #                         ]
    #                     },
    #                     200,
    #                 ),
    #             ),
    #         )
    #     ]
    #     return super()._monkeypatch(patches=patches)
