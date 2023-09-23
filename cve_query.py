import requests
from termcolor import colored

def search_cve_by_keyword(keyword):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    search_url = f"{base_url}?keyword={keyword}&resultsPerPage=10"
    
    try:
        response = requests.get(search_url)
        response.raise_for_status()
        cve_data = response.json()
        return cve_data
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None
def get_cvss(id):
    url = f"https://cve.circl.lu/api/cve/{id}"
    try: 
        response = requests.get(url)
        response.raise_for_status()
        cve_data = response.json()
        return cve_data["cvss"]
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None
    

def main():
    keyword = "jQuery 3.4.2"  # modify as needed
    cve_data = search_cve_by_keyword(keyword)
    print(get_cvss("CVE-2022-2031"))
    
    if cve_data:
        for cve_entry in cve_data["result"]["CVE_Items"]:
            cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"]
            description = cve_entry["cve"]["description"]["description_data"][0]["value"]
            cvss_score = get_cvss(id)
            try:
                cvss = float(cvss_score) if cvss_score !="None" else 0
            except:
                cvss =0
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
            print(colored(f"- CVE ID: {cve_id}",color))
            print(colored(f"- CVSS: {cvss_score}", color))
            print(colored(f"- Description: {description}", color))
            print("------")

if __name__ == "__main__":
    main()