import requests
from bs4 import BeautifulSoup

url = "https://99percentinvisible.org"

response = requests.get(url)

if response.status_code == 200:

    soup = BeautifulSoup(response.text, "html.parser")


    cms_markers = ["WordPress", "Joomla", "Drupal"]
    detected_cms = [cms for cms in cms_markers if cms in soup.text]

    if detected_cms:
        print(f"The web application is using CMS: {', '.join(detected_cms)}")
    else:
        print("No CMS detected.")

    js_libs = soup.find_all("script", src=True)
    if js_libs:
        print("Third-party JavaScript libraries used:")
        for js in js_libs:
            print(js["src"])
else:
    print("Failed to fetch the web page.")