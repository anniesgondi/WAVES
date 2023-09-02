import requests
from bs4 import BeautifulSoup
import argparse
import re
from termcolor import colored

# Wordpress regex


def parse():
    parser = argparse.ArgumentParser()
 
    # Adding optional argument
    parser.add_argument("-u", "--url", help = "URl to be crawled")
    
    # Read arguments from command line
    args = parser.parse_args()
    
    if args.url:
        print(colored( '[+] Given URL: ' + args.url, 'green'))
        return args.url
    
def is_wp(url):
    # Checks if the given url is a WordPress installation.
    print(colored("Detecting Wordpress version...", "blue"))
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
        r = requests.get(url)
        # Regex to detect version number, not working.
        # wp_match =  re.search(
        #         r'Version ([0-9]+\.[0-9]+\.?[0-9]*)',
        #         str(r.text)
        #     )
        if r:
            print(colored('[*] Wordpress CMS detected! :  ' , 'green') + url)
            return r #supposed to return the version number, but not working for now so returning just the response
    print("Wordpress not detected")
    

    
url = parse()

response = requests.get(url)

if response.status_code == 200:

    soup = BeautifulSoup(response.text, "html.parser")


    cms_markers = ["WordPress", "Joomla", "Drupal"]
    detected_cms = [cms for cms in cms_markers if cms in soup.text]

    # if detected_cms:
    #     print(f"The web application is using CMS: {', '.join(detected_cms)}")
    # else:
    #     print("No CMS detected.")

    js_libs = soup.find_all("script", src=True)
    if js_libs:
        print("Third-party JavaScript libraries used:")
        for js in js_libs:
            print(js["src"])
    
    print("[+] Detecting CMS...")
    wp_flag = is_wp(url)
    # if wp_flag:
    #     print("Wordpress version: "+wp_flag)
    
            
else:
    print("[!] Failed to fetch the web page.")