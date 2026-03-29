import os
import pandas as pd
import json
import time
import re

from Models.GeminiApi import bard



def buil_prompt(group_name,rapport) :
    prompt = f"""
    Remove the noise from this cyber threat attack report, mask groupe name = {group_name}  in the rapport field with [PLACEHOLDER]. This will allow students to analyze the report and attribute the incident to a known threat actor based on the techniques, tactics, procedures (TTPs), and any other relevant information described.

    Important:
    - Noise includes links, contact us sections, other article suggestions, or any information that does not relate to the report.

    Output format: only the report no extra sentences 
    
    Text:
    {rapport}
    """
    return prompt
def escape_json_string(s):
    # Replace problematic characters with their escaped equivalents
    s = s.replace('"', '\\"')  # Escape double quotes
    s = s.replace('\\', '\\\\')  # Escape backslashes
    s = s.replace('\b', '\\b')  # Escape backspace
    s = s.replace('\f', '\\f')  # Escape form feed
    s = s.replace('\n', '\\n')  # Escape newline
    s = s.replace('\r', '\\r')  # Escape carriage return
    s = s.replace('\t', '\\t')  # Escape tab
    
    # For non-printable or control characters in Unicode, escape using \uXXXX
    # Convert any non-ASCII characters to their Unicode escape sequence
    return ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in s)


# Read the CSV file into a DataFrame
json_filename = "rapport.json"
dirty_rapport = "reports_links_LMM.csv"

def clean_reports(dirty_rapport, json_filename):
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

    # Read the input CSV
    if not os.path.exists(dirty_rapport):
        print(f"Error: {dirty_rapport} not found.")
        return

    df = pd.read_csv(dirty_rapport, usecols=['URL', 'group_name', 'file_name']).reset_index(drop=True)
    
    # Filter out already processed URLs
    initial_count = len(df)
    df = df[~df['URL'].isin(processed_urls)]
    remaining_count = len(df)
    
    if remaining_count == 0:
        print("All reports are already cleaned.")
        return
        
    print(f"Processing {remaining_count} remaining reports (skipped {initial_count - remaining_count}).")

    # Process each row in the DataFrame
    for idx, row in df.iterrows():
        group_name = row['group_name']
        file_name = row['file_name']
        url = row['URL']
        
        file_path = f"rapport/{file_name}.txt"
        if not os.path.exists(file_path):
            print(f"  Warning: File not found {file_path}. Skipping.")
            continue

        # Read the content of the file
        with open(file_path, 'r', encoding='utf-8') as file:
            report_text = file.read()
            
        if not report_text.strip():
            print(f"  Warning: Empty report file {file_path}. Skipping.")
            continue

        print(f"  Cleaning report for {group_name} ({url})...")
        final_prompt = buil_prompt(str(group_name), str(report_text))
        
        try:
            response = bard(final_prompt)
            # Give Gemini a moment between calls
            time.sleep(2)
            alias_response = bard(f"give me alias (also known as) of this cyber attackers group :{group_name} . output format : split alias with coma (,) no extra sentences . exemple : lets say goup name : MuddyWater  .output exempla  : APT34, Crambus, Helix Kitten, OilRig ")
            alias = alias_response.split(",") if alias_response else []
            
            if response:
                # Escape backslashes in the report text
                response_escaped = escape_json_string(response)
                obj = {
                    "link": url,
                    "group_name": group_name,
                    "alias": [a.strip() for a in alias],
                    "rapport": response_escaped
                }
                with open(json_filename, 'a', encoding='utf-8') as json_file:
                    json.dump(obj, json_file, ensure_ascii=False)
                    json_file.write("\n")
                print(f"  [OK] Report added for {group_name}")
            else:
                print(f"  [Warning] Gemini returned empty response for {group_name}")
                
        except Exception as e:
            print(f"  [Error] Failed to process {group_name}: {e}")
            if "429" in str(e) or "quota" in str(e).lower():
                print("  Quota reached. Stopping for now.")
                break
            continue



