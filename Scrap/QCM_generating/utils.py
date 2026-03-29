import json

def clean_response(response):
    """
    Cleans the response by extracting valid JSON objects.
    """
    lines = response.split("\n")
    json_objects = []
    in_json_object = False
    json_buffer = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("{"):
            in_json_object = True
            json_buffer.append(line)
        elif stripped.startswith("}") and in_json_object:
            json_buffer.append(line)
            json_objects.append("\n".join(json_buffer))
            in_json_object = False
            json_buffer = []
        elif in_json_object:
            json_buffer.append(line)

    return json_objects

def sanitize_qcm(obj):
    """
    Ensures all MCQ fields are strings and cleans up unwanted formatting like 
    list wrapping or decorative brackets.
    """
    fields_to_clean = ["Question", "Option A", "Option B", "Option C", "Option D", "Correct Answer", "Explanation"]
    
    for field in fields_to_clean:
        val = obj.get(field)
        if val is None:
            continue
            
        # Handle list wrapping: ["text"] -> "text"
        if isinstance(val, list):
            val = " ".join([str(i) for i in val]) if len(val) > 0 else ""
        
        # Force string and strip whitespace
        val = str(val).strip()
        
        # Remove decorative brackets if model used them: "[Answer]" -> "Answer"
        if val.startswith('[') and val.endswith(']'):
            val = val[1:-1].strip()
            
        obj[field] = val
    return obj

def is_valid_qcm(obj, id_key):
    """
    Validates that a QCM object has the necessary technical content.
    """
    required_fields = [id_key, "Question", "Option A", "Option B", "Option C", "Option D", "Correct Answer"]
    
    for field in required_fields:
        val = obj.get(field)
        if val is None or str(val).strip() == "":
            return False
            
    if len(str(obj.get("Question")).strip()) < 10:
        return False
        
    return True
