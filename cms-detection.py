import requests
from bs4 import BeautifulSoup
import argparse
import re
from termcolor import colored
import xmltodict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
from file_to_pdf import generate_report, save_to_html
from library_detect import detect_libs
from cve_query import search_cve_by_keyword, get_cvss
from crawl import crawl_urls
from xss import check_xss

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



session = requests.Session()
retry = Retry(connect=3, backoff_factor=0.5)
adapter = HTTPAdapter(max_retries=retry)
session.mount('http://', adapter)
session.mount('https://', adapter)

data = {}

def parse():
    parser = argparse.ArgumentParser()
 
    # Adding optional argument
    parser.add_argument("-u", "--url", help = "URl to be crawled")
    parser.add_argument("-o","--output", help="File name of report to be generated")
    
    # Read arguments from command line
    args = parser.parse_args()
    
    arg_list = []
    if args.url:
        arg_list.append(args.url)
        print(colored( '[+] Given URL: ' + args.url, 'green'))
    if args.output:
        arg_list.append(args.output)
    return arg_list
    

def get_wp_version(url, response):
    version=0
    print(colored("[+] Detecting Wordpress version...", "blue"))
    version = ''
    
    r1 = re.findall(r'<meta name=\"generator\" content=\"WordPress (.*?)\"', response.text)
    if r1!=[]:
        version = r1[0]
    if version=='':
        response2 = requests.get(url +'/feed/',verify=False)
        r2 = re.findall(r'<generator>https://wordpress.org/\?v=(.*?)</generator>', response2.text)
        if r2!=[]:
            version = r2[0]
        if version == '':
            response3 = requests.get(url + '/wp-links-opml.php',verify=False)
            r3 = re.findall(r'generator=\"wordpress/(.*?)\"', response3.text)
            if r3!=[]:
                version = r3[0]

    if version == '':
        print(colored("[!] Wordpress version not detected", "red"))
    else:
        print(colored(f"[*] Wordpress version: {version}", "green"))
    return version
    
def is_wp(url):
    # Checks if the given url is a WordPress installation.
    print(colored("[+] Detecting Wordpress", "blue"))
    headers = {'user-agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)'}
    ping = requests.get(url, headers=headers,verify=False)
    # session = requests.Session()
    # retry = Retry(connect=3, backoff_factor=0.5)
    # adapter = HTTPAdapter(max_retries=retry)
    # session.mount('http://', adapter)
    # session.mount('https://', adapter)
    wp_signatures = {
            1: url + "/wp-login.php",
            2: url + "/wp-content/",
            3: url + "/wp-admin/",
            4: url + "/wp-cron.php",
            5: url + "/xmlrpc.php",
            6: url + "/wp-json/wp/v2/",
            7: url + "/wp-content/themes/",
        }
    for url in wp_signatures.values():
        r = session.get(url, headers=headers,verify=False)
        if r:
            print(colored('[*] Wordpress CMS detected! :  ' , 'green') + url)
            return get_wp_version(url,ping) #supposed to return the version number, but not working for now so returning just the response
    print(colored("[!] Wordpress CMS not detected","red"))
    
def get_joomla_version(url):
    version=0
    headers = {'Connection': 'keep-alive','Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

    properties ={'verify': False,'allow_redirects': True,'headers': headers
    }
    print(colored("[+] Detecting Joomla! version...","blue"))
    response = requests.get(f"{url}/language/en-GB/en-GB.xml",verify=False, **properties)
    
    res_headers= response.headers
    if response.ok and "application/xml" in res_headers  or "text/xml" in res_headers:
            data = xmltodict.parse(response.content)
            version = data["metafile"]["version"]
            print(colored(f"[*] Joomla version is: {version} ","green"))
    else:
        response = requests.get(f"{url}/administrator/manifests/files/joomla.xml")
        res_headers= response.headers
        if response.ok and "application/xml" in res_headers  or "text/xml" in res_headers:
            data = parse(response.content)
            version = data["extension"]["version"]
            print(colored(f"[*] Joomla version is: {version}","green"))
    return version
        
        
        
    
    
def is_joomla(url):
    version = 0
    print(colored("[+] Detecting Joomla!","blue"))
    response = requests.get(url,verify=False)
    if response.ok and '<meta name="generator" content="Joomla!' in response.text: 
        print(colored("[*] Joomla! CMS detected","green"))
        version = get_joomla_version(url)
        if not version:
            print(colored("[-] The Joomla! version could not be detected", "yellow"))                 
    else:
        print(colored("[!] Joomla! CMS not detected", "red"))
    return version
        
def is_drupal(url: str):
    print(colored("[+] Detecting Drupal...", "blue"))
    if not url.endswith('/'):
        url+='/'
    # session = requests.Session()
    # retry = Retry(connect=3, backoff_factor=0.5)
    # adapter = HTTPAdapter(max_retries=retry)
    # session.mount('http://', adapter)
    # session.mount('https://', adapter)

    drupal_signatures = [
      url + 'CHANGELOG.txt',
      url + 'core/CHANGELOG.txt',
      url + 'includes/bootstrap.inc',
      url + 'core/includes/bootstrap.inc',
      url + 'includes/database.inc',
      url + 'includes/database/database.inc',
      url + 'core/includes/database.inc'
    ]
    headers = {'user-agent': 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)'}
    version = 0
    drupal=False
    for signature in drupal_signatures:
        response = session.get(signature,headers=headers, verify=False)
        if response.ok:
            r = response.text.splitlines()
            for line in r:
                if "Drupal" in line:
                    drupal=True
                    v = re.search(r"([\d][.][\d]?[.]?[\d])", line)
                    v1 = re.search(r"(\d)", line)
                    if v is not None:
                        version = v.group(0)
                        break
                    if v1 is not None:
                        version = v1.group(0)
                        break
        if version!=0:
            break
    if drupal:
        print(colored("[*] Drupal CMS detected","green"))
    if version==0:
        print(colored("[!] Drupal CMS version not detected", "red"))
    else:
        print(colored(f"[*] Drupal version is: {version}","green"))
    return version


def detect_shopify(url):
    try:
        print(colored("[+] Detecting Shopify CMS...","blue"))
        response = requests.get(url,verify=False)
        response.raise_for_status()
        html_content = response.text
        shopify_patterns = [
            r"cdn\.shopify\.com", r"shopify-checkout",r"Powered by Shopify",]
        for pattern in shopify_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                print(colored("[*] Shopify CMS detected","green"))
        print(colored("[!] Shopify CMS not detected","red"))
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}"

print(''' __      _____   _____ ___ 
 \ \    / /_\ \ / / __/ __|
  \ \/\/ / _ \ V /| _|\__ \\
   \_/\_/_/ \_\_/ |___|___/
                           ''')
print("Web Application Vulnerability and Exploit Scanner")
print()
args = parse()
url = args[0]
filename=args[1]
data["target"]= url

response = requests.get(url, verify=False)

if response.status_code == 200:

    soup = BeautifulSoup(response.text, "html.parser")


    # if detected_cms:
    #     print(f"The web application is using CMS: {', '.join(detected_cms)}")
    # else:
    #     print("No CMS detected.")
    print(colored("[+] Detecting third-party libraries...", "blue")  )  
    try:
        detected_libs = detect_libs(url,soup,session)
    except:
        detected_libs=[]
                
    print()
    print(colored("[+] Detecting CMS...","blue"))
    wp_version = is_wp(url)
    joomla_version=0
    drupal_version=0
    if not wp_version:
        joomla_version = is_joomla(url)
        if not joomla_version:
            drupal_version = is_drupal(url)
    detect_shopify(url)
            
            
    detected_cms = {"Wordpress": wp_version, "Joomla": joomla_version, "Drupal": drupal_version}
    # Listing CVE's
    print()
    data["critical"]=0
    data["high"]=0
    data["medium"]=0
    data["low"]=0
    data["detected_libs"]=""
    data["cves"]=[]
    for cms in detected_cms:
        if detected_cms[cms]:
            data["detected_cms"]= f"{cms} (v {detected_cms[cms]})"
            print(colored(f"[+] Retrieving CVE details for {cms}...", "blue"))
            cve_data = search_cve_by_keyword(cms + " " + detected_cms[cms])
            if cve_data:
                for cve_entry in cve_data["result"]["CVE_Items"]:
                    cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"]
                    description = cve_entry["cve"]["description"]["description_data"][0]["value"]
                    cvss_score = get_cvss(cve_id)
                    try:
                        cvss = float(cvss_score) if cvss_score !="None" else 0
                    except:
                        cvss = 0
                    if cvss>9:
                        color = "red"
                        data["critical"]+=1
                    elif cvss>7:
                        color = "magenta"
                        data["high"]+=1
                    elif cvss>4:
                        color = "yellow"
                        data["medium"]+=1
                    elif cvss >0:
                        color = "green"
                        data["low"]+=1
                    else:
                        color = "white"
                    data["cves"].append({"id":cve_id, "cvss": cvss_score,"desc": description})
                    print(colored(f"- CVE ID: {cve_id}",color))
                    print(colored(f"- CVSS: {cvss_score}", color))
                    print(colored(f"- Description: {description}", color))
                    # data["cve_details"]
                    print("------")
    for lib in detected_libs:
        if detected_libs[lib]:
            data["detected_libs"]+= f"{lib} (v {detected_libs[lib]}), "
            print(colored(f"[+] Retrieving CVE details for {lib}...", "blue"))
            cve_data = search_cve_by_keyword(lib + " " + detected_libs[lib])
            if cve_data['resultsPerPage']!=0:
                for cve_entry in cve_data["result"]["CVE_Items"]:
                    cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"]
                    description = cve_entry["cve"]["description"]["description_data"][0]["value"]
                    cvss_score = get_cvss(cve_id)
                    cvss = float(cvss_score) if cvss_score !="None" else 0
                    if cvss>9:
                        color = "red"
                    elif cvss>7:
                        color = "magenta"
                    elif cvss>4:
                        color = "yellow"
                    elif cvss >0:
                        color = "green"
                    else:
                        color = "white"
                    data["cves"].append({"id":cve_id, "cvss": cvss_score,"desc": description})
                    print(colored(f"- CVE ID: {cve_id}",color))
                    print(colored(f"- CVSS: {cvss_score}", color))
                    print(colored(f"- Description: {description}", color))
                    print("------")
            else:
                print(colored(f"[#] Failed to fetch CVE details of {lib} from the database. Please try searching for CVE's manually", "yellow"))    
    try:
        rendered_html = generate_report(data)
        save_to_html(filename, rendered_html)
        print(colored(f"[*] Generated report file \'{filename}\' successfully!", "green"))
    except:
        print(colored("[!] Failed to generate report file", "red"))

    
    con = input(colored("[] Initial scanning done. Would you like to proceed with XSS scan? (y/n): "))
    if con!= 'y' and con!="Y":
        exit(0)
    
    print(colored("[+] Crawling URLS with GET parameters...", "blue"))
    crawl_urls(url, "crawled_links.txt")
    
    # Not executing from here
    print(colored("[*] Crawling phase complete. Checking for RXSS...", "blue"))
    payload = input(colored("[] Enter your XSS payload. Leave blank to use default payload (<script>alert('webscan')</script>): "))
    if payload:
        check_xss(payload, open("crawled_links.txt").readlines())
    else:
        check_xss("<script>alert('webscan')</script>", open("crawled_links.txt").readlines())
    
    
else:
    print("[!] Failed to fetch the web page.")