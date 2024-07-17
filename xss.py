#
from urllib.parse  import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning
from termcolor import colored
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_xss(payload,urls):
    checked=[]
    results = 0
    for url in urls:
        parse_result = urlparse(url)
        params = parse_qs(parse_result.query)
        new_query = ""
        for param in params:
            new_query+= f"&{param}={payload}"
        curr_url = parse_result.scheme + '://' + parse_result.netloc + parse_result.path + "?" + new_query.removeprefix("&")
        if curr_url not in checked:
            print(colored(f"[+] Now testing: {curr_url}"))
            response = requests.get(curr_url,verify=False)
            checked.append(curr_url)
            if response.ok and payload in response.text:
                print(colored("[*] Potential RXSS detected!","green"))
                print(colored(f"[*] Payload: {response.url}","green"))
                results +=1
    print(colored(f"[+] Detection complete. {results}  results found"))
# print(check_xss('"><script>alert(2)</script>', open("crawled_links.txt","r").readlines()))
