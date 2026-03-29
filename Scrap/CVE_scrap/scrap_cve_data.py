import requests
import csv
import os
import time
from requests.exceptions import RequestException

def extract_cve_ids_from_csv(filename):
    """
    Extracts CVE IDs from a CSV file.

    Args:
        filename (str): Path to the CSV file containing CVE IDs.

    Returns:
        list: A list of CVE IDs.
    """
    cve_ids = []
    if not isinstance(filename, str) or not os.path.exists(filename):
        return []
    with open(filename, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        try:
            next(reader)  # Skip the header row
        except StopIteration:
            return []
        for row in reader:
            if row:
                cve_ids.append(row[0])
    return cve_ids

def scrape_cve_data(cve_id, api_key=None):
    """
    Fetches detailed data for a given CVE ID from the NVD API 2.0.

    Args:
        cve_id (str): The CVE ID to fetch data for.
        api_key (str): Optional NVD API key.

    Returns:
        dict: A dictionary containing CVE details.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        "User-Agent": "MyPythonScraper (contact: faroukdaboussi2009@gmail.com)"
    }
    if api_key:
        headers['apiKey'] = api_key

    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 403:
            print(f"Rate limited or forbidden for {cve_id}. Sleeping 30s...")
            time.sleep(30)
            response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Error fetching {cve_id}: {e}")
        return None

    vulnerabilities = data.get('vulnerabilities', [])
    if not vulnerabilities:
        print(f"No vulnerability data found for {cve_id}")
        return None

    cve_data = vulnerabilities[0]['cve']
    
    # Description
    description = next((d['value'] for d in cve_data.get('descriptions', []) if d.get('lang') == 'en'), None)
    
    # Date published
    date_published = cve_data.get('published')
    
    # CVSS Vector String
    metrics = cve_data.get('metrics', {})
    vector_string = None
    
    if 'cvssMetricV31' in metrics:
        vector_string = metrics['cvssMetricV31'][0]['cvssData'].get('vectorString')
    elif 'cvssMetricV30' in metrics:
        vector_string = metrics['cvssMetricV30'][0]['cvssData'].get('vectorString')
    elif 'cvssMetricV2' in metrics:
        vector_string = metrics['cvssMetricV2'][0]['cvssData'].get('vectorString')
    
    # CWE IDs
    cwe_ids = []
    for weakness in cve_data.get('weaknesses', []):
        for desc in weakness.get('description', []):
            if desc.get('lang') == 'en':
                cwe_ids.append(desc['value'])
    
    # Hyperlinks
    hyperlinks = [ref.get('url') for ref in cve_data.get('references', [])]
    
    return {
        'CVE_ID': cve_id,
        'Description': description,
        'Date_Published': date_published,
        'CVSS_Vector_String': vector_string,
        'CWE_IDs': ', '.join(cwe_ids) if cwe_ids else None,
        'Hyperlinks': ', '.join(hyperlinks) if hyperlinks else None
    }

def save_to_csv(data, filename, mode='a'):
    """
    Saves data to a CSV file.

    Args:
        data (list): List of dictionaries containing data to save.
        filename (str): Path to the CSV file.
        mode (str): File open mode ('a' for append). Defaults to 'a'.
    """
    if not data:
        return
    keys = data[0].keys()
    file_exists = os.path.exists(filename) and os.path.getsize(filename) > 0
    with open(filename, mode, newline='', encoding='utf-8') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        if not file_exists:
            dict_writer.writeheader()
        dict_writer.writerows(data)

def count_csv_rows(file_path):
    """
    Counts the number of rows in a CSV file excluding the header.

    Args:
        file_path (str): Path to the CSV file.

    Returns:
        int: The number of rows in the CSV file.
    """
    if not os.path.exists(file_path):
        return 0
    
    with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        row_count = sum(1 for row in reader)
        return max(0, row_count - 1)  # Subtract the header row

def scrap_cve_data_from_links(input_source="Data/logs/cve_links.csv", output_filename="Data/collected_data/cve_data.csv", batch_size=10, api_key=None, overwrite=False):
    """
    Main function to process CVE IDs, fetch detailed data from NVD API, and save to CSV.

    Args:
        input_source (str or list): Path to the input CSV file or a list of CVE IDs. Defaults to 'Data/logs/cve_links.csv'.
        output_filename (str): Path to the output CSV file. Defaults to 'Data/collected_data/cve_data.csv'.
        batch_size (int): Number of records to save in each batch. Defaults to 10.
        api_key (str): Optional NVD API key.
        overwrite (bool): If True, clears the output file and restarts fetching from scratch.
    """
    if isinstance(input_source, list):
        cve_ids = input_source
        source_name = "provided list"
    else:
        cve_ids = extract_cve_ids_from_csv(input_source)
        source_name = input_source

    if not cve_ids:
        print(f"No CVE IDs found in {source_name}")
        return

    # Get already processed CVE IDs from the output file to skip them
    existing_ids = set()
    file_exists = os.path.exists(output_filename) and os.path.getsize(output_filename) > 0
    if file_exists and not overwrite:
        existing_ids = set(extract_cve_ids_from_csv(output_filename))
        print(f"Resuming: found {len(existing_ids)} already processed CVEs.")
    elif file_exists and overwrite:
        print(f"Overwrite enabled: Clearing {output_filename} and starting fresh.")
        # We'll just open it in 'w' mode during the first save or clear it now
        with open(output_filename, 'w', encoding='utf-8') as f:
            pass # Just clear it

    # Only process CVEs that aren't already in the output file
    cve_ids_to_process = [cid for cid in cve_ids if cid not in existing_ids]
    
    if not cve_ids_to_process:
        print("All CVEs in the input have already been processed.")
        return

    print(f"Total CVEs to fetch: {len(cve_ids_to_process)}")

    all_data = []
    total_cves = len(cve_ids_to_process)
    start_time = time.time()

    for index, cve_id in enumerate(cve_ids_to_process, start=1):
        data = scrape_cve_data(cve_id, api_key=api_key)
        if data:
            all_data.append(data)
        
        # To avoid rate limiting: 
        # With API key: 50 requests / 30 seconds (0.6s delay)
        # Without API key: 5 requests / 30 seconds (6s delay)
        delay = 0.61 if api_key else 6.1
        time.sleep(delay)

        # Save data in batches
        if len(all_data) >= batch_size or index == total_cves:
            save_to_csv(all_data, output_filename)
            total_saved = len(existing_ids) + index
            elapsed_time = time.time() - start_time
            processed_so_far = index
            if processed_so_far > 0:
                estimated_total_time = elapsed_time * (total_cves / processed_so_far)
                estimated_remaining_time = estimated_total_time - elapsed_time
                print(f"Total: {total_saved} (Saved {index} in this session). Remaining: {estimated_remaining_time:.2f}s")
            all_data = []

if __name__ == "__main__":
    # Example usage:
    # scrap_cve_data_from_links("cve_links.csv")
    pass
