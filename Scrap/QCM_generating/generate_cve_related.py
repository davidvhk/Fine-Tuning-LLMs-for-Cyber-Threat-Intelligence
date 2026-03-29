import csv
import json
import os
import time

from Models.OllamaApi import bard
from Scrap.QCM_generating.utils import clean_response, is_valid_qcm, sanitize_qcm

def generate_cves_qcm(cves, output_json_filename='Data/logs/QCM_CVE.json'):
    # Load existing progress
    existing_ids = set()
    all_qcms = []

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_json_filename), exist_ok=True)

    if os.path.exists(output_json_filename):
        try:
            with open(output_json_filename, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    if content.startswith('['):
                        all_qcms = json.loads(content)
                    else:
                        for line in content.split('\n'):
                            if line.strip():
                                data = json.loads(line)
                                all_qcms.append(data)

            for item in all_qcms:
                if 'CVE_ID' in item:
                    existing_ids.add(item['CVE_ID'])
            print(f"Loaded {len(existing_ids)} existing CVE MCQs from {output_json_filename}")
        except Exception as e:
            print(f"Warning: Could not load existing progress: {e}")

    # Initialize variables
    base_text = '''You are a cybersecurity expert specializing in Common Vulnerabilities and Exposures (CVE). Given the text below, please generate a maximum of 40 multiple-choice questions (MCQ) with four possible options.
    
    Output format: a series of JSON objects (one per question) with these keys:
    - "CVE_ID": the CVE ID from input
    - "Reference": The CVE ID (e.g. "CVE-2023-1234")
    - "Question": The technical question
    - "Option A": Choice A
    - "Option B": Choice B
    - "Option C": Choice C
    - "Option D": Choice D
    - "Correct Answer": A, B, C, or D
    - "Explanation": Brief explanation
    
    Output ONLY JSON objects, nothing else. No nested lists or arrays in values.
    '''

    # Filter out CVEs already processed
    todo_df = cves[~cves['CVE_ID'].isin(existing_ids)]

    if len(todo_df) == 0:
        print("All CVEs already have MCQs.")
        return all_qcms

    print(f"Generating MCQs for {len(todo_df)} remaining CVEs using Ollama...")

    max_cves_per_request = 10

    for i in range(0, len(todo_df), max_cves_per_request):
        batch = todo_df.iloc[i:i+max_cves_per_request]
        accumulated_text = base_text + "\n\n"

        for _, cve in batch.iterrows():
            text_representation = (
                f"CVE ID: {cve['CVE_ID']}\n"
                f"Description: {cve['Description']}\n"
                f"CVSS Vector String: {cve['CVSS_Vector_String']}\n"
                f"CWE IDs: {cve['CWE_IDs']}\n"
            )
            accumulated_text += text_representation + "\n\n"

        print(f"  Requesting Ollama for CVE batch {i//max_cves_per_request + 1}...")
        try:
            response = bard(accumulated_text)
            if not response:
                print("    Warning: Empty response. Skipping batch.")
                continue

            json_objects = clean_response(response)
            new_count = 0
            for obj_str in json_objects:
                try:
                    obj = json.loads(obj_str)
                    obj = sanitize_qcm(obj)
                    if is_valid_qcm(obj, 'CVE_ID'):
                        all_qcms.append(obj)
                        new_count += 1
                    else:
                        print(f"    Warning: Skipping empty/invalid CVE MCQ for {obj.get('CVE_ID', 'Unknown')}")
                except:
                    continue

            # Save progress incrementally
            with open(output_json_filename, 'w', encoding='utf-8') as f:
                json.dump(all_qcms, f, indent=4)

            print(f"    Added {new_count} new MCQs. Total: {len(all_qcms)}")
            time.sleep(2)

        except Exception as e:
            print(f"    Error processing CVE batch: {e}")
            continue

    return all_qcms
