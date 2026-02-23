import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def extract_forms(url):
    forms_data = []

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action")
            method = form.get("method", "GET").upper()

            # Resolve relative URLs
            action_url = urljoin(url, action) if action else url

            inputs = []
            for input_tag in form.find_all(["input", "textarea"]):
                name = input_tag.get("name")
                if name:
                    inputs.append(name)

            forms_data.append({
                "action": action_url,
                "method": method,
                "inputs": inputs
            })

    except Exception as e:
        forms_data.append({
            "error": f"Form extraction failed: {e}"
        })

    return forms_data