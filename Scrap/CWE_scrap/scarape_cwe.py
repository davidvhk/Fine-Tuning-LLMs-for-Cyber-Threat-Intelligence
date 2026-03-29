import re
import csv
import requests
import os
import zipfile
from bs4 import BeautifulSoup

def download_cwe_xml(target_path):
    """
    Downloads the latest CWE XML database from Mitre and extracts it.
    """
    url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    zip_path = target_path + ".zip"
    
    print(f"CWE database not found. Downloading latest version from {url}...")
    
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print("Download complete. Extracting...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # The zip contains one XML file, we need to find its name
            xml_filename = zip_ref.namelist()[0]
            zip_ref.extract(xml_filename, os.path.dirname(target_path))
            
            # Rename extracted file to match our expected target_path
            extracted_path = os.path.join(os.path.dirname(target_path), xml_filename)
            if os.path.exists(target_path):
                os.remove(target_path)
            os.rename(extracted_path, target_path)
            
        os.remove(zip_path)
        print(f"CWE database ready at {target_path}")
        return True
    except Exception as e:
        print(f"Failed to download CWE database: {e}")
        return False

def get_cwe_ids(data_path):
    """
    Extracts CWE IDs from the XML database file.
    """
    if not os.path.exists(data_path):
        if not download_cwe_xml(data_path):
            return []

    with open(data_path, 'r', encoding='utf-8') as file:
        xml_text = file.read()

    # Define a regular expression pattern to find ID and Name attributes in <Weakness> tags
    pattern = r'<Weakness\s+ID="(\d+)"\s+Name="([^"]+)".*?>'

    # Find all occurrences of the pattern in the XML text
    matches = re.findall(pattern, xml_text, re.DOTALL)
    ids = []
    for ID, Name in matches:
        ids.append(ID)
    return ids

def scrape_cwe_data(cwe_id):
    """
    Scrapes technical descriptions for a specific CWE from mitre.org.
    """
    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    headers = {
        "User-Agent": "MyPythonScraper via requests lib (contact: faroukdaboussi2009@gmail.com)"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CWE data for {cwe_id}: {e}")
        return None

    soup = BeautifulSoup(response.content, "html.parser")
    
    # Extracting Description
    description_div = soup.find("div", id=f"oc_{cwe_id}_Description")
    description = description_div.text.strip() if description_div else ""

    # Extracting Extended Description
    extended_description_div = soup.find("div", id=f"oc_{cwe_id}_Extended_Description")
    extended_description = extended_description_div.text.strip() if extended_description_div else ""

    # Extracting References
    references_div = soup.find("div", id=f"oc_{cwe_id}_References")
    references = [a.get("href") for a in references_div.find_all("a") if a.get("href")] if references_div else []

    data = {
        "ID": cwe_id,
        "Description": description,
        "Extended Description": extended_description,
        "References": "|".join(references)
    }

    return data

def save_cwe_batch(data, filename):
    """
    Appends a batch of CWE data to the CSV file.
    """
    file_exists = os.path.exists(filename) and os.path.getsize(filename) > 0
    if not data:
        return
    keys = data[0].keys()
    with open(filename, 'a', newline='', encoding='utf-8') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        if not file_exists:
            dict_writer.writeheader()
        dict_writer.writerows(data)

def scrap_cwe(id_list_filename='Data/logs/cwec_v4.15.xml', output_file='Data/collected_data/cwe_data.csv', batch_size=10, overwrite=False):
    """
    Main function to coordinate CWE scraping with auto-download, batch saving and resume capability.
    """
    # Ensure parent directory for logs exists
    os.makedirs(os.path.dirname(id_list_filename), exist_ok=True)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    list_of_cwe_ids = get_cwe_ids(id_list_filename)
    if not list_of_cwe_ids:
        print("Could not retrieve CWE IDs. Database file might be missing or corrupt.")
        return
    
    # Handle Overwrite/Resume
    existing_ids = set()
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        # Check if it's a Git LFS pointer
        is_lfs = False
        with open(output_file, 'r', encoding='utf-8') as f:
            first_line = f.readline()
            if first_line.startswith("version https://git-lfs"):
                is_lfs = True
        
        if overwrite or is_lfs:
            reason = "Overwrite enabled" if overwrite else "Git LFS pointer detected"
            print(f"{reason}: Clearing {output_file} and starting fresh.")
            with open(output_file, 'w', encoding='utf-8') as f:
                pass
        else:
            with open(output_file, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader, None) # header
                existing_ids = {row[0] for row in reader if row}
            print(f"Resuming CWE scraping: {len(existing_ids)} already processed.")

    ids_to_scrape = [cid for cid in list_of_cwe_ids if cid not in existing_ids]
    
    if not ids_to_scrape:
        print("All CWEs have already been scraped.")
        return

    print(f"Total CWEs to fetch: {len(ids_to_scrape)}")
    
    scraped_batch = []
    for i, cwe_id in enumerate(ids_to_scrape, 1):
        data = scrape_cwe_data(cwe_id)
        if data:
            scraped_batch.append(data)
            print(f"  CWE-{cwe_id} is done.")
        
        # Save every batch_size
        if len(scraped_batch) >= batch_size or i == len(ids_to_scrape):
            if scraped_batch:
                save_cwe_batch(scraped_batch, output_file)
                scraped_batch = []
                print(f"Progress: {len(existing_ids) + i}/{len(list_of_cwe_ids)} saved to {output_file}")
