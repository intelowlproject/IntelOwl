import requests
import json
from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

class BGPRanking(classes.ObservableAnalyzer):
    '''
    wrapper for https://github.com/D4-project/BGP-Ranking
    '''

    observable_name:str
    period:int #optional

    def update(self) -> bool:
        pass
    def run(self):
        urls = {
                "getASN":"https://bgpranking-ng.circl.lu/ipasn_history/?ip=",
                "getASNRank":"https://bgpranking-ng.circl.lu/json/asn",
                "getASNHistory":"https://bgpranking-ng.circl.lu/json/asn_history"
                }
        finalresposne = {}

        #get ASN from ip
        try:
            response= requests.get(urls["getASN"]+self.observable_name)
            response.raise_for_status()
            response = response.json()
            finalresposne['asn'] = response['response'][list(response['response'].keys())[0]]['asn']
        

        #get ASN rank from extracted ASN
        
            response = requests.post(urls["getASNRank"], data=json.dumps({"asn":finalresposne['asn']}))   
            response.raise_for_status()
            response = response.json()
            finalresposne['asn_description']=response['response']['asn_description']
            finalresposne['asn_rank'] = response['response']['ranking']['rank']
            finalresposne['asn_position'] = response['response']['ranking']['position']

            if self.period:
                #get ASN history from extracted ASN
                response = requests.post(urls["getASNHistory"], data=json.dumps({"asn":finalresposne['asn'], "period":self.period}))   
                response.raise_for_status()
                response = response.json()
                finalresposne['asn_history'] = response['response']['asn_history']
            
        except requests.exceptions.RequestException as e:
            raise AnalyzerRunException(e)
        except TypeError as e:
            raise AnalyzerRunException(e)

        return finalresposne


    @classmethod
    def _monkeypatch(cls):
        response = {
            "key": "191.121.10.0",
            "effective_opts": {"type": "ip4", "limit": 100, "wildcard": False},
            "status": "finished",
            "query_key": "191.121.10.0",
            "records": {},
            "records_returned": 0,
            "limited": False,
            "error": None,
        }
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(response, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
