import os
import requests
import zipfile

def download_capec_csv(target_path):
    """
    Downloads the latest CAPEC CSV database and extracts it.
    """
    url = "https://capec.mitre.org/data/csv/1000.csv.zip"
    zip_path = target_path + ".zip"
    
    # Check if we need to download (missing or LFS)
    needs_download = False
    if not os.path.exists(target_path):
        needs_download = True
    else:
        with open(target_path, 'r', encoding='utf-8') as f:
            first_line = f.readline()
            if first_line.startswith("version https://git-lfs"):
                needs_download = True
                print("CAPEC.csv is an LFS pointer. Re-downloading actual data...")

    if not needs_download:
        return True

    print(f"Downloading CAPEC database from {url}...")
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()
        
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print("Extraction in progress...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # MITRE zip usually contains one CSV file
            csv_filename = [name for name in zip_ref.namelist() if name.endswith('.csv')][0]
            zip_ref.extract(csv_filename, os.path.dirname(target_path))
            
            extracted_path = os.path.join(os.path.dirname(target_path), csv_filename)
            if os.path.exists(target_path):
                os.remove(target_path)
            os.rename(extracted_path, target_path)
            
        os.remove(zip_path)
        print(f"CAPEC database ready at {target_path}")
        return True
    except Exception as e:
        print(f"Failed to download CAPEC database: {e}")
        return False
