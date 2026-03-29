import csv
import requests
from bs4 import BeautifulSoup
import re
import time
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
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

def count_words(text):
    """Count words in a text."""
    return len(re.findall(r'\w+', text))

def fetch_with_retries(url, retries=RETRY_COUNT, delay=RETRY_DELAY):
    """Fetch URL content with retry logic using requests."""
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)
            if response.status_code == 200:
                return response
            else:
                print(f"  Request failed: {response.status_code} (Attempt {attempt + 1}/{retries})")
        except Exception as e:
            print(f"  Request error: {e} (Attempt {attempt + 1}/{retries})")
        time.sleep(delay)
    return None

def process_links(row):
    """Process and validate links from a row without Selenium."""
    valid_links = []
    links_str = str(row.get('links', ''))
    links = [l.strip() for l in links_str.split(',') if l.strip()]
    
    # Names to look for (main name + aliases)
    names_to_match = [str(row.get('group_name', '')).lower()]
    aliases_str = str(row.get('aliases', ''))
    if aliases_str:
        aliases = [a.strip().lower() for a in aliases_str.split(',') if a.strip()]
        names_to_match.extend(aliases)
    
    # Ensure directory for individual reports exists
    os.makedirs("rapport", exist_ok=True)
    
    link_num = 1
    for link in links:
        if not link: continue
        
        # Try to clean URL (Gemini sometimes adds extra chars)
        link = link.strip('."\'')
        
        print(f"  Validating: {link}")
        try:
            response = fetch_with_retries(link)
            if response is None:
                # Try adding/removing trailing slash as a last ditch effort for 404s
                if link.endswith('/'):
                    alt_link = link[:-1]
                else:
                    alt_link = link + '/'
                print(f"    Retrying alternative: {alt_link}")
                response = fetch_with_retries(alt_link, retries=1)
                
            if response is None:
                print(f"    [FAIL] Reachability")
                continue
                
            page_content = response.text
            soup = BeautifulSoup(page_content, 'html.parser')
            
            # Try to find main content
            article = soup.find('article') or soup.find('main') or \
                      soup.find('div', class_=re.compile(r'content|post|article|body', re.I)) or \
                      soup.find('section', class_=re.compile(r'content|post|article', re.I)) or \
                      soup.find('body')

            if article:
                # Remove script and style elements
                for element in article(["script", "style", "nav", "header", "footer"]):
                    element.decompose()
                    
                article_text = article.get_text(separator=' ', strip=True)
                word_count = count_words(article_text)
                text_lower = article_text.lower()

                # Validation criteria: check if ANY of the names/aliases appear
                match_count = 0
                for name in names_to_match:
                    if name and len(name) > 2: # Avoid tiny strings
                        count = text_lower.count(name)
                        match_count += count
                
                # Check for "External ID" like G1014 if available
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

    # Ensure output files exist with headers at the start
    if not os.path.exists(temp_valid_file):
        with open(temp_valid_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['group_id', 'group_name', 'links'])
            writer.writeheader()

    if not os.path.exists(valid_reports_links_csv):
        with open(valid_reports_links_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['URL', 'group_name', 'file_name'])
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
        
        # Save progress
        with open(temp_valid_file, 'a', newline='', encoding='utf-8') as f:
            fieldnames = ['group_id', 'group_name', 'links']
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writerows([row_dict])

    # Final conversion to the required output format
    if os.path.exists(temp_valid_file):
        with open(temp_valid_file, 'r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            with open(valid_reports_links_csv, 'w', newline='', encoding='utf-8') as outfile:
                fieldnames = ['URL', 'group_name', 'file_name']
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in reader:
                    if not row.get('links'): continue
                    group_name = row['group_name']
                    links = [l.strip() for l in row['links'].split(',') if l.strip()]
                    for idx, link in enumerate(links, 1):
                        writer.writerow({
                            'URL': link, 
                            'group_name': group_name, 
                            'file_name': f"{group_name}R{idx}".replace(' ', '_')
                        })

def scrap_reports(reports_links_csv, reports_data_tsv):
    valid_reports_links_csv = 'Data/logs/valid_reports_links.csv'
    validate_reports(reports_links_csv, valid_reports_links_csv)
    
    cleaned_report_json = "Data/logs/rapport.json"
    clean_reports(valid_reports_links_csv, json_filename=cleaned_report_json)
    
    preper_report_to_tsv(cleaned_report_json, reports_data_tsv, reports_links_csv) 
