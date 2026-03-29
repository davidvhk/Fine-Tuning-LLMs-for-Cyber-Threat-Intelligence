import csv
import json
import os
import time

from Models.GeminiApi import bard



def generate_capec_qcm(capecs, output_json_filename='Data/logs/QCM_CAPEC.json'):
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
                if 'CAPEC_ID' in item:
                    # Support both "CAPEC-1" and "1" formats
                    cid = str(item['CAPEC_ID'])
                    if not cid.startswith('CAPEC-'):
                        cid = f"CAPEC-{cid}"
                    existing_ids.add(cid)
            print(f"Loaded {len(existing_ids)} existing CAPEC MCQs from {output_json_filename}")
        except Exception as e:
            print(f"Warning: Could not load existing progress: {e}")

    # Initialize variables
    base_text = '''You are a cybersecurity expert specializing in Common Attack Pattern Enumeration and Classification (CAPEC). Given the text below, please generate a maximum of 20 multiple-choice questions (MCQ)  with four possible options ( 1 question for each CAPEC provided in the text below).
... (rest of prompt instructions) ...
'''

    # Filter out CAPECs already processed
    def get_full_id(cid):
        cid_str = str(cid)
        return cid_str if cid_str.startswith('CAPEC-') else f"CAPEC-{cid_str}"

    todo_df = capecs[~capecs['ID'].apply(get_full_id).isin(existing_ids)]

    if len(todo_df) == 0:
        print("All CAPECs already have MCQs.")
        return all_qcms

    print(f"Generating MCQs for {len(todo_df)} remaining CAPECs...")

    max_capecs_per_request = 10

    for i in range(0, len(todo_df), max_capecs_per_request):
        batch = todo_df.iloc[i:i+max_capecs_per_request]
        accumulated_text = base_text + "\n\n"

        for _, capec in batch.iterrows():
            text_representation = (f"CAPEC ID: {capec['ID']}\n"
                                f"Name: {capec['Name']}\n"
                                f"Abstraction: {capec['Abstraction']}\n"
                                f"Status: {capec['Status']}\n"
                                f"Description: {capec['Description']}\n"
                                f"Alternate Terms: {capec['Alternate Terms']}\n"
                                f"Likelihood Of Attack: {capec['Likelihood Of Attack']}\n"
                                f"Typical Severity: {capec['Typical Severity']}\n"
                                f"Related Attack Patterns: {capec['Related Attack Patterns']}\n"
                                f"Execution Flow: {capec['Execution Flow']}\n"
                                f"Prerequisites: {capec['Prerequisites']}\n"
                                f"Skills Required: {capec['Skills Required']}\n"
                                f"Resources Required: {capec['Resources Required']}\n"
                                f"Indicators: {capec['Indicators']}\n"
                                f"Consequences: {capec['Consequences']}\n"
                                f"Mitigations: {capec['Mitigations']}\n"
                                f"Related Weaknesses: {capec['Related Weaknesses']}\n")
            accumulated_text += text_representation + "\n\n"

        print(f"  Requesting Gemini for CAPEC batch {i//max_capecs_per_request + 1}...")
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
                    all_qcms.append(obj)
                    new_count += 1
                except:
                    continue

            # Save progress incrementally
            with open(output_json_filename, 'w', encoding='utf-8') as f:
                json.dump(all_qcms, f, indent=4)

            print(f"    Added {new_count} new MCQs. Total: {len(all_qcms)}")
            time.sleep(5)

        except Exception as e:
            print(f"    Error processing CAPEC batch: {e}")
            if "429" in str(e) or "quota" in str(e).lower():
                print("    Quota reached. Stopping CAPEC QCM generation.")
                break
            continue

    return all_qcms