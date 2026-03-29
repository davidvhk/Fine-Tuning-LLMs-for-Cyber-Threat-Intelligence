import csv
import json
import os
import time

from Models.GeminiApi import bard


def clean_response(response):
        """
        Cleans the response by extracting valid JSON objects.
        
        Parameters:
        - response (str): The response from the bard function.
        
        Returns:
        - cleaned_objects (list): A list of cleaned JSON objects.
        """
        lines = response.split("\n")
        json_objects = []
        in_json_object = False
        json_buffer = []

        for line in lines:
            if line.startswith("{"):
                in_json_object = True
                json_buffer.append(line)
            elif line.startswith("}") and in_json_object:
                json_buffer.append(line)
                json_objects.append("\n".join(json_buffer))
                in_json_object = False
                json_buffer = []
            elif in_json_object:
                json_buffer.append(line)

        return json_objects

def generate_cwes_qcm(cwes, output_json_filename='Data/logs/QCM_CWE.json'):
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
                if 'CWE_ID' in item:
                    # Support both "CWE-79" and "79" formats
                    cid = str(item['CWE_ID'])
                    if not cid.startswith('CWE-'):
                        cid = f"CWE-{cid}"
                    existing_ids.add(cid)
            print(f"Loaded {len(existing_ids)} existing CWE MCQs from {output_json_filename}")
        except Exception as e:
            print(f"Warning: Could not load existing progress: {e}")

    # Initialize variables
    base_text = '''You are a cybersecurity expert specializing in Common Weakness Enumeration (CWE). Given the text below, please generate a maximum of 20 multiple-choice questions (MCQ) ( 1 question for each CWE provided in the text below) with four possible options.
... (rest of prompt instructions) ...
'''

    # Filter out CWEs already processed
    # cwes is likely a DataFrame, and its ID column might be 79 or CWE-79
    def get_full_id(cid):
        cid_str = str(cid)
        return cid_str if cid_str.startswith('CWE-') else f"CWE-{cid_str}"

    todo_df = cwes[~cwes['ID'].apply(get_full_id).isin(existing_ids)]
    
    if len(todo_df) == 0:
        print("All CWEs already have MCQs.")
        return all_qcms

    print(f"Generating MCQs for {len(todo_df)} remaining CWEs...")

    max_cwes_per_request = 10
    
    for i in range(0, len(todo_df), max_cwes_per_request):
        batch = todo_df.iloc[i:i+max_cwes_per_request]
        accumulated_text = base_text + "\n\n"
        
        for _, cwe in batch.iterrows():
            text_representation = f"CWE ID: {cwe['ID']}\nDescription: {cwe['Description']} . {cwe['Extended Description']} \n"
            accumulated_text += text_representation + "\n\n"

        print(f"  Requesting Gemini for CWE batch {i//max_cwes_per_request + 1}...")
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
            print(f"    Error processing CWE batch: {e}")
            if "429" in str(e) or "quota" in str(e).lower():
                print("    Quota reached. Stopping CWE QCM generation.")
                break
            continue

    return all_qcms

