import json
import csv
import re
import time
import requests
import os
import random
from Models.GeminiApi import bard
from googlesearch import search

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

def get_links_via_search(group_name, max_results=5):
    """
    Uses Google Search to find high-quality threat report URLs for a group.
    """
    print(f"Searching Google for: {group_name}...")
    
    reputable_domains = [
        'mandiant.com', 'crowdstrike.com', 'securelist.com', 'kaspersky.com', 
        'unit42.paloaltonetworks.com', 'microsoft.com', 'cisa.gov', 
        'welivesecurity.com', 'checkpoint.com', 'talosintelligence.com',
        'sentinelone.com', 'symantec-enterprise-blogs.security.com',
        'zscaler.com', 'proofpoint.com', 'recordedfuture.com', 'trendmicro.com'
    ]
    
    query = f'"{group_name}" threat report technical analysis'
    urls = []
    
    try:
        # Perform Google search
        # num_results=10 to get a good sample, then we filter
        search_results = search(query, num_results=15, lang="en")
        
        for url in search_results:
            if not url or not url.startswith('http'):
                continue
            
            # Filter out noise and social media
            noise = ["/groups/", "/tags/", "/search?", "twitter.com", "facebook.com", "linkedin.com", "youtube.com"]
            if any(x in url.lower() for x in noise):
                continue
                
            # Prioritize reputable domains
            is_reputable = any(domain in url.lower() for domain in reputable_domains)
            
            if url not in urls:
                if is_reputable:
                    urls.insert(0, url) # Put top sources at the beginning
                else:
                    urls.append(url)
        
        # Limit to requested count
        final_urls = urls[:max_results]
        print(f"  Found {len(final_urls)} technical URLs.")
        return final_urls
            
    except Exception as e:
        print(f"  Google Search Error for {group_name}: {e}")
        return []

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

def scrap_reports_links(extracted_data, csv_file_path='Data/logs/reports_links.csv'):
    # Load existing progress
    results = []
    if os.path.exists(csv_file_path):
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
    else:
        existing_ids = set()
            
    todo = [item for item in extracted_data if str(item['group_id']).strip() not in existing_ids]
    
    if not todo:
        print("All report links already discovered.")
        return

    print(f"Discovering links for {len(todo)} remaining groups using Google Search...")
    
    for item in todo:
        group_name = item['group_name']
        
        # Use Google Search for real URLs
        report_urls = get_links_via_search(group_name)
        
        if report_urls:
            item['links'] = ', '.join(report_urls)
            results.append(item)
            save_to_csv(results, csv_file_path)
            print(f"  [OK] Saved links for {group_name}.")
        else:
            print(f"  [FAIL] No links found for {group_name}.")
        
        # CRITICAL: Sleep between requests to avoid Google blocking (429)
        # Random delay between 10 and 20 seconds for Google
        delay = random.uniform(10, 20)
        print(f"  Sleeping {delay:.1f}s to respect search engine limits...")
        time.sleep(delay)
        
    print(f"Reports links discovery complete. Results saved to {csv_file_path}")
