import json
import os
import time

from Models.OllamaApi import bard
from Scrap.QCM_generating.utils import clean_response, is_valid_qcm, sanitize_qcm

def generate_techniques_qcm(techniques, output_json_filename='Data/logs/QCM_TECHNIQUES.json'):
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
                        data = json.loads(content)
                        all_qcms = data
                    else:
                        for line in content.split('\n'):
                            if line.strip():
                                data = json.loads(line)
                                all_qcms.append(data)
                                
            for item in all_qcms:
                if 'Technique_ID' in item:
                    existing_ids.add(item['Technique_ID'])
            print(f"Loaded {len(existing_ids)} existing Technique MCQs from {output_json_filename}")
        except Exception as e:
            print(f"Warning: Could not load existing progress: {e}")

    # Initialize variables
    base_text = '''You are a cybersecurity expert specializing in MITRE ATT&CK techniques. Given the text below, please generate a maximum of 10 multiple-choice questions (MCQ) with four possible options.
    
    Output format: a series of JSON objects (one per question) with these keys:
    - "Technique_ID": the Technique ID from input (e.g. "T1059")
    - "Reference": The Technique ID
    - "Question": The technical question
    - "Option A": Choice A
    - "Option B": Choice B
    - "Option C": Choice C
    - "Option D": Choice D
    - "Correct Answer": A, B, C, or D
    - "Explanation": Brief explanation
    
    Output ONLY JSON objects, nothing else. No nested lists or arrays in values.
    '''

    # Filter out techniques that are already processed
    todo_techniques = [t for t in techniques if t.get('ID') not in existing_ids]
    
    if not todo_techniques:
        print("All techniques already have MCQs.")
        return all_qcms

    print(f"Generating MCQs for {len(todo_techniques)} remaining techniques using Ollama...")

    max_techniques_per_request = 5
    
    for i in range(0, len(todo_techniques), max_techniques_per_request):
        batch = todo_techniques[i:i+max_techniques_per_request]
        accumulated_text = base_text + "\n\n"
        
        for technique in batch:
            text_representation = json.dumps(technique, indent=2)
            accumulated_text += text_representation + "\n\n"

        print(f"  Requesting Ollama for batch {i//max_techniques_per_request + 1}...")
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
                    if is_valid_qcm(obj, 'Technique_ID'):
                        all_qcms.append(obj)
                        new_count += 1
                    else:
                        print(f"    Warning: Skipping empty/invalid Technique MCQ for {obj.get('Technique_ID', 'Unknown')}")
                except:
                    continue
            
            # Save progress incrementally
            with open(output_json_filename, 'w', encoding='utf-8') as f:
                json.dump(all_qcms, f, indent=4)
            
            print(f"    Added {new_count} new MCQs. Total: {len(all_qcms)}")
            time.sleep(2)
            
        except Exception as e:
            print(f"    Error processing batch: {e}")
            continue
            
    return all_qcms
