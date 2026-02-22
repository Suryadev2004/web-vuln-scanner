import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_links(url):
    discovered_links = set()

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all("a", href=True):
            link = urljoin(url, tag["href"])
            parsed_link = urlparse(link)

            if parsed_link.netloc == urlparse(url).netloc:
                clean_link = parsed_link.scheme + "://" + parsed_link.netloc + parsed_link.path
                discovered_links.add(clean_link)

    except requests.exceptions.RequestException:
        pass

    return discovered_links