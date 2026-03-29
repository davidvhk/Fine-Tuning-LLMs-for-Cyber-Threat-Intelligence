import os
import pandas as pd
import json
import time
import re

def escape_json_string(s):
    # Replace problematic characters with their escaped equivalents
    s = s.replace('"', '\\"')  # Escape double quotes
    s = s.replace('\\', '\\\\')  # Escape backslashes
    s = s.replace('\b', '\\b')  # Escape backspace
    s = s.replace('\f', '\\f')  # Escape form feed
    s = s.replace('\n', '\\n')  # Escape newline
    s = s.replace('\r', '\\r')  # Escape carriage return
    s = s.replace('\t', '\\t')  # Escape tab
    return ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in s)

def mask_group_name(text, group_name, aliases=None):
    """
    Locally masks the group name and its aliases in the text.
    """
    names_to_mask = [group_name]
    if aliases:
        if isinstance(aliases, list):
            names_to_mask.extend(aliases)
        elif isinstance(aliases, str):
            names_to_mask.extend([a.strip() for a in aliases.split(',') if a.strip()])
            
    # Sort by length descending to avoid partial matches
    names_to_mask = sorted([n for n in names_to_mask if len(n) > 2], key=len, reverse=True)
    
    masked_text = text
    for name in names_to_mask:
        # Use regex for word boundary matching
        pattern = re.compile(re.escape(name), re.IGNORECASE)
        masked_text = pattern.sub("[PLACEHOLDER]", masked_text)
        
    return masked_text

def clean_reports(valid_reports_links_csv, json_filename="rapport.json"):
    """
    Processes the validated reports, masks the names, and saves to JSON.
    NO GEMINI USED.
    """
    # Load already processed URLs to skip them
    processed_urls = set()
    if os.path.exists(json_filename):
        try:
            with open(json_filename, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if 'link' in data:
                                processed_urls.add(data['link'])
                        except:
                            continue
            print(f"Loaded {len(processed_urls)} already processed reports from {json_filename}")
        except Exception as e:
            print(f"Error loading {json_filename}: {e}")

    # Read the input CSV (this should be the output of validation)
    if not os.path.exists(valid_reports_links_csv):
        print(f"Error: {valid_reports_links_csv} not found.")
        return

    df = pd.read_csv(valid_reports_links_csv).reset_index(drop=True)
    
    # Filter out already processed URLs
    if 'URL' in df.columns:
        df = df[~df['URL'].isin(processed_urls)]
    elif 'links' in df.columns:
        df = df[~df['links'].isin(processed_urls)]
    
    if len(df) == 0:
        print("All validated reports are already in the final JSON.")
        return
        
    print(f"Adding {len(df)} new validated reports to {json_filename}...")

    # Process each row
    for idx, row in df.iterrows():
        group_name = row['group_name']
        url = row.get('URL', row.get('links'))
        aliases = row.get('aliases', '')
        file_name = row.get('file_name', '')
        
        if not file_name:
            # Fallback if file_name is missing
            file_name = f"{group_name}_R1".replace(' ', '_').replace('/', '_')
            
        file_path = os.path.join("rapport", f"{file_name}.txt")
        
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                report_text = f.read()
            
            if report_text.strip():
                print(f"  Processing {file_name}.txt for {group_name}...")
                
                # Mask the name locally
                cleaned_text = mask_group_name(report_text, group_name, aliases)
                
                obj = {
                    "link": url,
                    "group_name": group_name,
                    "alias": [a.strip() for a in str(aliases).split(',') if a.strip()],
                    "rapport": escape_json_string(cleaned_text)
                }
                
                with open(json_filename, 'a', encoding='utf-8') as json_file:
                    json.dump(obj, json_file, ensure_ascii=False)
                    json_file.write("\n")
            else:
                print(f"  Warning: Empty text file {file_path}")
        else:
            print(f"  Warning: No text file found at {file_path}")

    print(f"Final report processing complete.")
