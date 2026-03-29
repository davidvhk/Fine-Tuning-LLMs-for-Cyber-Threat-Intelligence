import json
import re
import os
import requests

def download_stix_data(target_path):
    """
    Downloads the latest MITRE ATT&CK STIX data.
    """
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    print(f"STIX data not found. Downloading from {url}...")
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, 'w', encoding='utf-8') as f:
            json.dump(response.json(), f)
        print(f"STIX data saved to {target_path}")
        return True
    except Exception as e:
        print(f"Failed to download STIX data: {e}")
        return False

def extract_techniques_base_data(data='Data/STIX_enterprise_attack.json'):
    if not os.path.exists(data):
        if not download_stix_data(data):
            return {}
            
    # Load the JSON data from the file
    with open(data, 'r', encoding='utf-8') as file:
        data_json = json.load(file)

    objects = data_json['objects']
    
    # Define mapping from STIX IDs to human-readable objects
    id_map = {obj['id']: obj for obj in objects}
    
    # Results dictionary
    extracted_data = {
        'attack_pattern': [],
        'malware': [],
        'tool': [],
        'intrusion_set': [],
        'campaign': [],
        'course_of_action': [],
        'relationship': []
    }

    # First pass: Extract objects and store by type
    for obj in objects:
        obj_type = obj['type'].replace('-', '_')
        if obj_type in extracted_data:
            # Extract basic attributes
            info = {
                'id': obj['id'],
                'name': obj.get('name'),
                'description': obj.get('description', ''),
                'External ID': '',
                'CAPEC IDs': [],
                'CWE IDs': []
            }
            
            # Extract External IDs (Txxxx, Gxxxx, etc.)
            for ref in obj.get('external_references', []):
                source = ref.get('source_name')
                ext_id = ref.get('external_id')
                if not ext_id: continue
                
                if source == 'mitre-attack':
                    info['External ID'] = ext_id
                elif source == 'capec':
                    info['CAPEC IDs'].append(ext_id)
                elif source == 'cwe':
                    info['CWE IDs'].append(ext_id)
            
            # Type specific attributes
            if obj_type == 'attack_pattern':
                info['Platforms'] = obj.get('x_mitre_platforms', [])
                info['Detection'] = obj.get('x_mitre_detection', '')
                info['Kill Chain Phases'] = [p.get('phase_name') for p in obj.get('kill_chain_phases', [])]
            
            extracted_data[obj_type].append(info)
        elif obj['type'] == 'relationship':
            extracted_data['relationship'].append(obj)

    return extracted_data, id_map

def scrap_data_related_to_techniques(techniques_base_data):
    # This is now mostly handled by the extract function
    # but we keep the structure for compatibility
    data, id_map = techniques_base_data
    
    attack_patterns = data['attack_pattern']
    intrusion_sets = data['intrusion_set']
    campaigns = data['campaign']
    malwares = data['malware']
    tools = data['tool']
    course_of_actions = data['course_of_action']
    relationships = data['relationship']

    # Map technique STIX IDs to their objects for easy access
    tech_map = {tp['id']: tp for tp in attack_patterns}

    # Process relationships to build the cross-references
    for rel in relationships:
        rel_type = rel.get('relationship_type')
        source_id = rel.get('source_ref')
        target_id = rel.get('target_ref')
        description = rel.get('description', '')

        # Skip relationships with missing IDs
        if not source_id or not target_id:
            continue

        # We are primarily interested in things related to techniques
        if target_id.startswith('attack-pattern'):
            tech = tech_map.get(target_id)
            if not tech: continue

            source_obj = id_map.get(source_id)
            if not source_obj: continue
            
            source_type = source_obj['type']
            source_name = source_obj.get('name', 'Unknown')
            source_ext_id = ''
            for ref in source_obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    source_ext_id = ref.get('external_id', '')

            # Add to the appropriate list in the technique object
            rel_info = {
                'id': source_ext_id,
                'name': source_name,
                'comment': description
            }

            if source_type == 'malware':
                tech.setdefault('related_malwares', []).append(rel_info)
            elif source_type == 'tool':
                tech.setdefault('related_tools', []).append(rel_info)
            elif source_type == 'intrusion-set':
                tech.setdefault('related_intrusion_sets', []).append(rel_info)
            elif source_type == 'campaign':
                tech.setdefault('related_campaigns', []).append(rel_info)
            elif source_type == 'course-of-action':
                tech.setdefault('mitigations', []).append(rel_info)

    return attack_patterns, intrusion_sets, campaigns, malwares, tools, course_of_actions

def populate_attack_patterns_with_scrapped_data(attack_patterns, malwares, tools, intrusion_sets, campaigns, course_of_actions):
    # In the new logic, relationships are already populated in scrap_data_related_to_techniques
    # so we just return the attack_patterns as they are.
    return attack_patterns

def clean_attack_pattern(data):
    # Clean up the detection field from references
    url_pattern = r'\(https://attack\.mitre\.org/.*?\)'
    for obj in data:
        if obj.get('Detection'):
            obj['Detection'] = re.sub(url_pattern, '', obj['Detection'])
    return data
