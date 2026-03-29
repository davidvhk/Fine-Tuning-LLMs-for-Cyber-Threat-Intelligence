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

def generate_techniques_qcm(techniques, output_json_filename='Data/logs/QCM_TECHNIQUES.json'):
    # Load existing progress
    existing_ids = set()
    all_qcms = []
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_json_filename), exist_ok=True)
    
    if os.path.exists(output_json_filename):
        try:
            with open(output_json_filename, 'r', encoding='utf-8') as f:
                # The file might be a JSON list or multiple objects
                content = f.read().strip()
                if content:
                    if content.startswith('['):
                        data = json.loads(content)
                        all_qcms = data
                    else:
                        # Assume line-separated JSON objects
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
... (rest of prompt instructions) ...
'''

    # Filter out techniques that are already processed
    todo_techniques = [t for t in techniques if t.get('ID') not in existing_ids]
    
    if not todo_techniques:
        print("All techniques already have MCQs.")
        return all_qcms

    print(f"Generating MCQs for {len(todo_techniques)} remaining techniques...")

    max_techniques_per_request = 5
    
    for i in range(0, len(todo_techniques), max_techniques_per_request):
        batch = todo_techniques[i:i+max_techniques_per_request]
        accumulated_text = base_text + "\n\n"
        
        for technique in batch:
            text_representation = json.dumps(technique, indent=2)
            accumulated_text += text_representation + "\n\n"

        print(f"  Requesting Gemini for batch {i//max_techniques_per_request + 1}...")
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
            print(f"    Error processing batch: {e}")
            if "429" in str(e) or "quota" in str(e).lower():
                print("    Quota reached. Stopping QCM generation.")
                break
            continue
            
    return all_qcms


