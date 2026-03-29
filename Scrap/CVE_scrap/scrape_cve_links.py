import requests
import csv
import os
import time
from datetime import datetime, timedelta

def get_cve_links(start_index=0, results_per_page=1000, api_key=None, start_date=None, end_date=None):
    """
    Fetches CVE IDs from the NVD API 2.0 within a specific date range.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }
    
    if start_date and end_date:
        params["pubStartDate"] = start_date
        params["pubEndDate"] = end_date

    headers = {
        "User-Agent": "MyPythonScraper (contact: faroukdaboussi2009@gmail.com)"
    }
    if api_key:
        headers['apiKey'] = api_key

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        if response.status_code == 403:
            print(f"Rate limited or forbidden. Sleeping 30s...")
            time.sleep(30)
            response = requests.get(url, headers=headers, params=params, timeout=60)
        
        if response.status_code != 200:
            print(f"Error {response.status_code}: {response.reason}")
            if 'message' in response.headers:
                print(f"API Message: {response.headers['message']}")
            return [], 0
            
        data = response.json()
    except Exception as e:
        print(f"Error fetching data at index {start_index}: {e}")
        return [], 0

    total_results = data.get('totalResults', 0)
    cve_links = []
    for vuln in data.get('vulnerabilities', []):
        cve_id = vuln['cve']['id']
        cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        cve_links.append({'CVE ID': cve_id, 'URL': cve_url})
    
    return cve_links, total_results

def count_csv_rows(file_path):
    """
    Counts the number of rows in the CSV file excluding the header.
    """
    if not os.path.exists(file_path):
        return 0
    
    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        row_count = sum(1 for row in reader)
        return max(0, row_count - 1)

def scrape_all_cve_links(output_file='Data/logs/cve_links.csv', api_key=None, start_year=None, overwrite=False):
    """
    Fetches all CVE links using the NVD API and writes them to a CSV file.
    """
    results_per_page = 1000
    fieldnames = ['CVE ID', 'URL']
    
    if start_year:
        # Range-based download
        current_date = datetime(start_year, 1, 1)
        end_of_time = datetime.now()
        
        # Load existing IDs to avoid duplicates unless overwriting
        existing_ids = set()
        file_exists = os.path.exists(output_file) and os.path.getsize(output_file) > 0
        if file_exists and not overwrite:
            with open(output_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None) # Skip header
                existing_ids = {row[0] for row in reader if row}
            print(f"Resuming: {len(existing_ids)} links already in {output_file}")
        else:
            mode = 'w'
            if overwrite:
                print(f"Overwrite enabled: Clearing {output_file} and starting fresh.")
            with open(output_file, mode, newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

        while current_date < end_of_time:
            window_end = current_date + timedelta(days=110)
            if window_end > end_of_time:
                window_end = end_of_time
            
            s_str = current_date.strftime("%Y-%m-%dT00:00:00.000Z")
            e_str = window_end.strftime("%Y-%m-%dT23:59:59.999Z")
            
            print(f"Fetching range: {s_str} to {e_str}")
            
            range_index = 0
            range_total = 1 
            
            while range_index < range_total:
                batch, range_total = get_cve_links(range_index, results_per_page, api_key, s_str, e_str)
                if batch:
                    # Filter out IDs we already have
                    new_links = [link for link in batch if link['CVE ID'] not in existing_ids]
                    if new_links:
                        with open(output_file, 'a', newline='', encoding='utf-8') as csvfile:
                            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                            writer.writerows(new_links)
                        # Add new IDs to our set to prevent duplicates within the same run
                        for link in new_links:
                            existing_ids.add(link['CVE ID'])
                        print(f"  Added {len(new_links)} new links to file.")
                    
                    range_index += len(batch)
                    print(f"  Progress in range: {range_index} / {range_total}")
                else:
                    if range_total == 0: break
                    print("  Error in batch, retrying...")
                    time.sleep(10)
                
                delay = 0.61 if api_key else 6.1
                time.sleep(delay)
            
            current_date = window_end + timedelta(seconds=1)
    else:
        # Full download (legacy)
        existing_rows = count_csv_rows(output_file)
        start_index = existing_rows
        print(f"Starting full fetch at index: {start_index}")
        
        first_batch, total_results = get_cve_links(start_index, results_per_page, api_key)
        if not first_batch and total_results == 0:
             return output_file

        file_exists = os.path.exists(output_file) and os.path.getsize(output_file) > 0
        with open(output_file, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()
            writer.writerows(first_batch)
        
        current_index = start_index + len(first_batch)
        while current_index < total_results:
            delay = 0.61 if api_key else 6.1
            time.sleep(delay)
            print(f"Fetching CVEs starting at index: {current_index} / {total_results}")
            batch, _ = get_cve_links(current_index, results_per_page, api_key)
            if batch:
                with open(output_file, 'a', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writerows(batch)
                current_index += len(batch)
            else:
                time.sleep(10)

    return output_file

if __name__ == "__main__":
    pass
