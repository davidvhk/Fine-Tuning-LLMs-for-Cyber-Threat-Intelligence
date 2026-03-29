import json
import csv
import re
import time
import requests
import os
import random
from bs4 import BeautifulSoup
from ddgs import DDGS

def get_existing_groups(intrusion_sets='Data/intrusion_sets.json'):
    if not os.path.exists(intrusion_sets):
        print(f"Warning: {intrusion_sets} not found.")
        return []

    with open(intrusion_sets, 'r') as json_file:
        data = json.load(json_file)

    extracted_data = []
    for item in data:
        name = item.get('Intrusion Set Name')
        ext_id = item.get('External ID')
        if name and ext_id:
            extracted_data.append({'group_id': ext_id, 'group_name': name, 'links': '', 'aliases': ''})
    return extracted_data

def get_links_via_ddg_lib(group_name, max_results=10):
    """
    Uses the DDGS library to find high-quality technical threat report URLs.
    Implements a robust multi-query strategy with refined technical keywords.
    """
    print(f"Searching for: {group_name}...")
    
    reputable_domains = [
        'mandiant.com', 'crowdstrike.com', 'securelist.com', 'kaspersky.com', 
        'unit42.paloaltonetworks.com', 'microsoft.com', 'cisa.gov', 
        'welivesecurity.com', 'checkpoint.com', 'talosintelligence.com',
        'sentinelone.com', 'symantec.com', 'zscaler.com', 'proofpoint.com', 
        'recordedfuture.com', 'trendmicro.com', 'fireeye.com', 'intezer.com'
    ]
    
    # Refined search queries for maximum technical depth
    queries = [
        f'"{group_name}" technical analysis report IOCs TTPs',
        f'"{group_name}" MITRE ATT&CK techniques analysis',
        f'site:mandiant.com OR site:kaspersky.com "{group_name}" analysis',
        f'"{group_name}" malware analysis whitepaper'
    ]
    
    found_urls = []
    try:
        with DDGS() as ddgs:
            for query in queries:
                print(f"  Attempting query: {query}")
                try:
                    # Search using text() without timelimit to find the best historical reports
                    ddgs_gen = ddgs.text(query, region='wt-wt', safesearch='off')
                    count = 0
                    for r in ddgs_gen:
                        href = r['href']
                        
                        # Filter for noise
                        noise = ["/groups/", "/tags/", "/search?", "twitter.com", "facebook.com", "linkedin.com", "youtube.com", "instagram.com", "reddit.com", "github.com", "wikipedia.org"]
                        if any(x in href.lower() for x in noise):
                            continue
                        
                        if href not in found_urls:
                            found_urls.append(href)
                            count += 1
                        
                        if count >= 4: # Stop after 4 hits per query to keep diversity
                            break
                            
                    if len(found_urls) >= max_results:
                        break
                        
                except Exception as query_e:
                    print(f"    Query failure: {query_e}")
                    continue
                
                # Small delay between queries for the same group to avoid rate-limiting
                time.sleep(random.uniform(2, 4))
                    
    except Exception as e:
        print(f"  Critical search error with library: {e}")

    # Prioritize reputable sources
    reputable_hits = []
    other_hits = []
    
    for u in found_urls:
        if any(domain in u.lower() for domain in reputable_domains):
            reputable_hits.append(u)
        else:
            other_hits.append(u)
            
    final_urls = (reputable_hits + other_hits)[:max_results]
    print(f"  [FOUND] {len(final_urls)} technical URLs for {group_name}")
    for u in final_urls:
        print(f"    - {u}")
    return final_urls

def save_to_csv(data, file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['group_id', 'group_name', 'aliases', 'links']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            links_val = row.get('links', '')
            if isinstance(links_val, list):
                links_val = ', '.join(links_val)
            
            writer.writerow({
                'group_id': row.get('group_id', ''),
                'group_name': row.get('group_name', ''),
                'aliases': row.get('aliases', ''),
                'links': links_val
            })

def scrap_reports_links(extracted_data, csv_file_path='Data/logs/reports_links.csv', force_refresh=False):
    """
    Main entry point for report link discovery.
    """
    results = []
    existing_ids = set()
    
    if not force_refresh and os.path.exists(csv_file_path):
        try:
            with open(csv_file_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                results = list(reader)
                
            valid_results = [r for r in results if r.get('links') and 'http' in str(r.get('links'))]
            print(f"Loaded {len(valid_results)} valid group links from cache.")
            existing_ids = {str(row['group_id']).strip() for row in valid_results}
            results = valid_results 
        except Exception as e:
            print(f"Warning: Error reading cache {csv_file_path}: {e}")
            results = []
            existing_ids = set()
            
    todo = [item for item in extracted_data if str(item['group_id']).strip() not in existing_ids]
    
    if not todo:
        print("All report links already discovered.")
        return

    print(f"Discovering high-signal technical links for {len(todo)} groups using DDGS...")
    
    for item in todo:
        group_name = item['group_name']
        report_urls = get_links_via_ddg_lib(group_name)
        
        if report_urls:
            item['links'] = ', '.join(report_urls)
            # Filter results list for updating
            results = [r for r in results if r['group_id'] != item['group_id']]
            results.append(item)
            save_to_csv(results, csv_file_path)
            print(f"  [OK] Saved technical links for {group_name}.")
        else:
            print(f"  [FAIL] No technical links found for {group_name}.")
        
        # Consistent pacing to respect rate limits
        delay = random.uniform(7, 12)
        time.sleep(delay)
        
    print(f"Reports links discovery complete. Results saved to {csv_file_path}")
