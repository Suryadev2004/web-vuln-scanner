import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_links(base_url):
    discovered_urls = set()

    try:
        response = requests.get(base_url)
        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):
            href = link["href"]

            # Convert relative URLs to absolute
            full_url = urljoin(base_url, href)

            # Parse domain
            parsed_base = urlparse(base_url)
            parsed_url = urlparse(full_url)

            # Only keep same-domain links
            if parsed_base.netloc == parsed_url.netloc:
                discovered_urls.add(full_url)

    except requests.exceptions.RequestException:
        pass

    return discovered_urls