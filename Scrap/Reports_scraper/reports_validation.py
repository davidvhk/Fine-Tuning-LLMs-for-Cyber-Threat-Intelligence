import csv
import requests
from bs4 import BeautifulSoup
import re
import time
import random
import pandas as pd
import os

from Scrap.Reports_scraper.preper_data import preper_report_to_tsv
from Scrap.Reports_scraper.scrap_raports import clean_reports

# Configurations
SLEEP_TIME = 2
RETRY_COUNT = 3
RETRY_DELAY = 2
MAX_WORD_COUNT = 8000
MIN_OCCURRENCES = 2

# Browser-like headers to avoid blocking
BASE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,video/mp4,video/webm,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "cross-site",
    "Referer": "https://www.google.com/"
}

def count_words(text):
    """Count words in a text."""
    return len(re.findall(r'\w+', text))

def fetch_with_retries(url, retries=RETRY_COUNT, delay=RETRY_DELAY):
    """Fetch URL content with multiple fallback strategies for Cloudflare/403s."""
    
    # Strategy 1: Requests with modern headers
    session = requests.Session()
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
    ]

    for attempt in range(retries):
        current_ua = user_agents[attempt % len(user_agents)]
        headers = BASE_HEADERS.copy()
        headers["User-Agent"] = current_ua
        
        try:
            # First try hitting the root domain to get cookies
            domain = "/".join(url.split("/")[:3])
            try:
                session.get(domain, headers={"User-Agent": current_ua}, timeout=10)
            except:
                pass
            
            response = session.get(url, headers=headers, timeout=30, allow_redirects=True)
            if response.status_code == 200:
                return response
            elif response.status_code == 403:
                print(f"  Requests failed (403). Trying fallback for {url}")
                # Strategy 2: urllib.request (different TLS fingerprint)
                import urllib.request
                import ssl
                import gzip
                
                try:
                    req = urllib.request.Request(url, headers=headers)
                    context = ssl._create_unverified_context()
                    with urllib.request.urlopen(req, timeout=20, context=context) as u_resp:
                        if u_resp.status == 200:
                            content = u_resp.read()
                            encoding = u_resp.info().get('Content-Encoding')
                            if encoding == 'gzip':
                                content = gzip.decompress(content)
                            elif encoding == 'deflate':
                                try:
                                    import zlib
                                    content = zlib.decompress(content)
                                except:
                                    pass
                                    
                            class MockResponse:
                                def __init__(self, text):
                                    self.text = text
                                    self.status_code = 200
                            return MockResponse(content.decode('utf-8', errors='replace'))
                except Exception as ue:
                    print(f"    Urllib fallback also failed: {ue}")
            else:
                print(f"  Request failed: {response.status_code} (Attempt {attempt + 1}/{retries})")
        except Exception as e:
            print(f"  Request error: {e}")
        
        if attempt < retries - 1:
            time.sleep(delay + random.uniform(1, 3))
            
    return None

def process_links(row):
    """Process and validate links from a row without Selenium."""
    valid_links = []
    links_str = str(row.get('links', ''))
    links = [l.strip() for l in links_str.split(',') if l.strip()]
    
    # Names to look for (main name + aliases)
    names_to_match = [str(row.get('group_name', '')).lower()]
    aliases_str = str(row.get('aliases', ''))
    if aliases_str and str(aliases_str).lower() != 'nan':
        aliases = [a.strip().lower() for a in str(aliases_str).split(',') if a.strip()]
        names_to_match.extend(aliases)
    
    # Ensure directory for individual reports exists
    os.makedirs("rapport", exist_ok=True)
    
    link_num = 1
    for link in links:
        if not link: continue
        link = link.strip('."\'')
        
        print(f"  Validating: {link}")
        try:
            response = fetch_with_retries(link)
            if response is None:
                # Try adding/removing trailing slash
                alt_link = link[:-1] if link.endswith('/') else link + '/'
                print(f"    Retrying alternative: {alt_link}")
                response = fetch_with_retries(alt_link, retries=1)
                
            if response is None:
                print(f"    [FAIL] Reachability")
                continue
                
            page_content = response.text
            try:
                soup = BeautifulSoup(page_content, 'lxml')
            except Exception:
                soup = BeautifulSoup(page_content, 'html.parser')
            
            article = soup.find('article') or \
                      soup.find('main') or \
                      soup.find('div', class_=re.compile(r'content|post|article|body|main|entry|story', re.I)) or \
                      soup.find('section', class_=re.compile(r'content|post|article|body|main', re.I)) or \
                      soup.find('div', id=re.compile(r'content|post|article|body|main', re.I)) or \
                      soup.find('body')

            if article:
                for element in article(["script", "style", "nav", "header", "footer", "aside"]):
                    element.decompose()
                    
                article_text = article.get_text(separator=' ', strip=True)
                if len(article_text) < 200 and article.name != 'body':
                    article = soup.find('body')
                    if article:
                        for element in article(["script", "style", "nav", "header", "footer", "aside"]):
                            element.decompose()
                        article_text = article.get_text(separator=' ', strip=True)

                word_count = count_words(article_text)
                text_lower = article_text.lower()

                match_count = 0
                for name in names_to_match:
                    if name and len(name) > 2:
                        match_count += text_lower.count(name)
                
                gid = str(row.get('group_id', '')).lower()
                if gid:
                    match_count += text_lower.count(gid)

                if word_count < MAX_WORD_COUNT and match_count >= MIN_OCCURRENCES:
                    valid_links.append(link)
                    file_name = f"{row.get('group_name', 'Unknown')}_R{link_num}.txt".replace(' ', '_').replace('/', '_')
                    file_path = os.path.join("rapport", file_name)
                    with open(file_path, 'w', encoding='utf-8') as file:
                        file.write(article_text)
                    link_num += 1
                    print(f"    [OK] Matches: {match_count}, Words: {word_count}")
                else:
                    reason = "too long" if word_count >= MAX_WORD_COUNT else f"insufficient name matches ({match_count})"
                    print(f"    [INVALID] {reason}")
            else:
                print(f"    [ERROR] No content found")
        
        except Exception as e:
            print(f"    [CRASH] {e}")

    return ', '.join(valid_links)

def load_existing_csv(file_path):
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            return list(reader)
    except Exception:
        return []

def validate_reports(reports_links='Data/logs/reports_links.csv', valid_reports_links_csv='Data/logs/valid_reports_links.csv'):
    temp_valid_file = 'Data/logs/temp_valid_reports_links.csv'
    os.makedirs(os.path.dirname(temp_valid_file), exist_ok=True)

    if not os.path.exists(temp_valid_file):
        with open(temp_valid_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['group_id', 'group_name', 'aliases', 'links'])
            writer.writeheader()

    existing_data = load_existing_csv(temp_valid_file)
    processed_groups = {row['group_id'] for row in existing_data}
    
    if not os.path.exists(reports_links):
        print(f"Error: {reports_links} not found.")
        return

    try:
        extracted_data = pd.read_csv(reports_links)
    except Exception as e:
        print(f"Error reading {reports_links}: {e}")
        return
    
    for i, row in extracted_data.iterrows():
        gid = str(row.get('group_id', ''))
        if gid in processed_groups:
            continue
            
        print(f"Validating reports for: {row['group_name']} ({i+1}/{len(extracted_data)})")
        row_dict = row.to_dict()
        row_dict['links'] = process_links(row_dict)
        
        with open(temp_valid_file, 'a', newline='', encoding='utf-8') as f:
            fieldnames = ['group_id', 'group_name', 'aliases', 'links']
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writerows([row_dict])

    if os.path.exists(temp_valid_file):
        with open(temp_valid_file, 'r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            with open(valid_reports_links_csv, 'w', newline='', encoding='utf-8') as outfile:
                fieldnames = ['URL', 'group_name', 'aliases', 'file_name']
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in reader:
                    if not row.get('links'): continue
                    group_name = row['group_name']
                    aliases = row.get('aliases', '')
                    links = [l.strip() for l in row['links'].split(',') if l.strip()]
                    for idx, link in enumerate(links, 1):
                        writer.writerow({
                            'URL': link, 
                            'group_name': group_name, 
                            'aliases': aliases,
                            'file_name': f"{group_name}R{idx}".replace(' ', '_')
                        })

def scrap_reports(reports_links_csv, reports_data_tsv):
    valid_reports_links_csv = 'Data/logs/valid_reports_links.csv'
    validate_reports(reports_links_csv, valid_reports_links_csv)
    
    cleaned_report_json = "Data/logs/rapport.json"
    clean_reports(valid_reports_links_csv, json_filename=cleaned_report_json)
    
    preper_report_to_tsv(cleaned_report_json, reports_data_tsv, reports_links_csv) 
