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

def main():
    keyword = "jQuery 3.4.2"  # modify as needed
    cve_data = search_cve_by_keyword(keyword)
    
    if cve_data:
        for cve_entry in cve_data["result"]["CVE_Items"]:
            cve_id = cve_entry["cve"]["CVE_data_meta"]["ID"]
            description = cve_entry["cve"]["description"]["description_data"][0]["value"]
            print(f"- CVE ID: {cve_id}")
            print(f"- Description: {description}")
            print("------")

if __name__ == "__main__":
    main()