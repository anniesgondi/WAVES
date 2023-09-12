from termcolor import colored
import re
def detect_libs(url, soup, session):
    jquery_f=False
    jquery_v=0
    lodash_f=False
    lodash_v=0
    modernizr_f=False
    modernizr_v=0
    js_libs = soup.find_all("script", src=True)
    links=[]
    if js_libs:
        # for js in js_libs:
        #     print(js["src"])
        for link in js_libs:
            if not link.get('src').startswith('http'):
                links.append(url+link.get('src'))
            else:
                links.append(link.get('src'))
    

    for link in links:
        if "jquery.min" in str(link).lower():
            url = session.get(link)
            versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)
            jquery_v=versions[0]
            jquery_f=True
        if "lodash.min" in str(link).lower():
            url = session.get(link)
            versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)
            lodash_v=versions[0]
            lodash_f=True
        if "modernizr" in str(link).lower():
            url = session.get(link)
            versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)
            modernizr_v=versions[0]
            modernizr_f=True
        if "jquery" in str(link).lower() and not jquery_f:
            print(colored("[+] Fetching expected jQuery version. May provide false positives..."))
            url = session.get(link)
            versions = re.findall(r'\d[0-9a-zA-Z._:-]+',url.text)
            jquery_v=versions[0]
            jquery_f=True
    if jquery_f:
        print(colored("[*] JQuery detected","green"))
        print(colored(f"[*] JQuery version: {jquery_v}","green"))
    if lodash_f:
        print(colored("[*] Lodash detected","green"))
        print(colored(f"[*] Lodash version: {lodash_v}","green"))
    if modernizr_f:
        print(colored("[*] Modernizr detected","green"))
        print(colored(f"[*] Modernizr version: {modernizr_v}","green"))
    return {"jQuery": jquery_v,"Lodash": lodash_v,"Modernizr": modernizr_v}
    