import logging

import requests
from bs4 import BeautifulSoup

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class ExpandURL(ObservableAnalyzer):
    def find_redirection_url(self, response: requests.Response) -> str | None:
        logger.info(f"Finding redirect URL in {response.url}")
        try:
            html_content = response.text
            soup = BeautifulSoup(html_content, features="html.parser")
            refresh_meta_tag = soup.find("meta", attrs={"http-equiv": "refresh"})

            # following block checks if the response content contains any meta refresh tags
            # if yes then, capture and return the redirection url
            if refresh_meta_tag is not None and "url" in refresh_meta_tag["content"].lower():
                _, url_text = refresh_meta_tag["content"].split(";")
                redirect_url = url_text.strip()[4:]
                logger.info(f"Found redirect URL: {redirect_url}")
                return redirect_url

        except KeyError as e:
            raise AnalyzerRunException(f'META refresh tag doesn\'t contain "content" key: {e}')

        except Exception as e:
            raise AnalyzerRunException(f"Unable to find redirection URL: {e}")

        logger.info(f"No redirect URL found for {response.url}, returning None")
        return None

    def expand_url(self, url) -> list[str]:
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/138.0.0.0 Safari/537.36"
        }
        no_more_redirects = False
        redirection_chain = []
        logger.info(f"Expanding {url}")
        try:
            while no_more_redirects is False:
                final_response = requests.get(url, headers=headers, allow_redirects=True)
                final_response.raise_for_status()
                for response in final_response.history:
                    redirection_chain.append(response.url)

                if final_response.is_redirect is False:
                    redirection_chain.append(final_response.url)
                    redirect_url = self.find_redirection_url(final_response)
                    if not redirect_url:
                        no_more_redirects = True
                    else:
                        redirection_chain.append(redirect_url)
                        url = redirect_url

            # previous loop runs in a way that for some conditions final url is added twice,
            # so removing duplicates
            if len(redirection_chain) > 1 and redirection_chain[-1] == redirection_chain[-2]:
                redirection_chain.pop()

        except requests.HTTPError as e:
            raise AnalyzerRunException(f"Unable to make a request : {e}")

        except Exception as e:
            raise AnalyzerRunException(f"Unable to expand URL for {self.observable_name}: {e}")
        logger.info("Expanding URL complete, returning with redirection chain")
        return redirection_chain

    @classmethod
    def update(cls):
        pass

    def run(self):
        redirection_chain = self.expand_url(self.observable_name)
        return {
            "actual_url": redirection_chain[-1],
            "fake_url": redirection_chain[0],
            "redirection_chain": redirection_chain,
        }
