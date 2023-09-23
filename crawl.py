import scrapy
from scrapy import cmdline
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
import requests
from urllib.parse import urljoin

import subprocess

crawled_links = []
# This class is a spider for scraping data from wikipedia
class LinkSpider(scrapy.Spider):
    name = 'all'
    allowed_domains= []

    start_urls = []
    

    def __init__(self, url: str, filename):
        self.start_urls.append(url.removesuffix('/'))
        self.filename=filename
        
        url = url.removeprefix("http://")
        url = url.removeprefix("https://")
        url = url.removeprefix("www.")
        self.allowed_domains.append(url)
        open(self.filename,"w").close()
        
    
    rules = (
    Rule(LinkExtractor(), callback='parse_item', follow=True),
)
    
    def parse(self, response):
        if "=" in response.url:
           with open(self.filename, "a+") as f:
               f.write(response.url + "\n")
        print(response.url)
        for href in response.css('a::attr(href)'):
            yield response.follow(href, self.parse)
    
        
            
def crawl_urls(url,filename):
    subprocess.run(f"scrapy runspider crawl.py --nolog -a url={url}  -a filename={filename}".split())
    return     
        
    
# crawl_urls("https://testfire.net", "testcrawl.txt")

# # print(crawled_links)
# check_xss("<script>alert(1)</script>", crawled_links)


  
