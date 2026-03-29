import pandas as pd
import numpy as np
import re
import os
from Models.OllamaApi import bard

def build_prompt_single(report_text):
    """
    Builds a prompt for a single report to determine if it's high-quality CTI data.
    """
    prompt = f'''Analyze the following Cyber Threat Intelligence report (truncated). 
    Determine if it contains detailed descriptions of attack techniques (TTPs) or Indicators of Compromise (IOCs).
    
    Report:
    {str(report_text)[:1500]}...
    
    Output format:
    Result: [1 if high-signal CTI, else 0]
    Reason: [One short sentence explaining why]
    
    Example:
    Result: 1
    Reason: Contains specific IP addresses and detailed phishing techniques.
    '''
    return prompt

def parse_single_response(response):
    """
    Parses the model response to find the 0/1 result and the reason.
    """
    res = {'value': None, 'reason': "No reason provided"}
    result_match = re.search(r'Result:\s*([01])', response, re.IGNORECASE)
    if result_match:
        res['value'] = int(result_match.group(1))
    else:
        fallback_match = re.search(r'\b([01])\b', response)
        if fallback_match:
            res['value'] = int(fallback_match.group(1))

    reason_match = re.search(r'Reason:\s*(.*)', response, re.IGNORECASE)
    if reason_match:
        res['reason'] = reason_match.group(1).strip()
    return res

def deep_validation(tta, final_reports="IOC_rapports.tsv"):
    """
    Validates reports one by one with resume logic.
    """
    progress_file = "Data/logs/validation_progress.csv"
    os.makedirs("Data/logs", exist_ok=True)

    print(f"Loading reports from {tta}...")
    try:
        df = pd.read_csv(tta, sep="\t")
    except Exception as e:
        print(f"Error loading {tta}: {e}")
        return

    # Load existing progress if available
    processed_links = set()
    if os.path.exists(progress_file):
        try:
            progress_df = pd.read_csv(progress_file)
            processed_links = set(progress_df['link'].tolist())
            print(f"Resuming: {len(processed_links)} reports already processed.")
        except Exception as e:
            print(f"Warning: Could not read progress file: {e}. Starting fresh.")

    total_reports = len(df)
    remaining_df = df[~df['link'].isin(processed_links)]
    
    if remaining_df.empty:
        print("All reports have already been processed.")
    else:
        print(f"Total reports to validate: {total_reports} ({len(remaining_df)} remaining)")

        # Process remaining reports
        for i, (_, row) in enumerate(remaining_df.iterrows()):
            report_num = len(processed_links) + 1
            actor = row.get('group_name', 'Unknown')
            link = row['link']
            
            prompt = build_prompt_single(row['rapport'])
            resp = bard(prompt)
            parsed = parse_single_response(resp)
            
            status = "PASSED" if parsed['value'] == 1 else "REJECTED"
            color_code = "\033[92m" if parsed['value'] == 1 else "\033[91m"
            reset_code = "\033[0m"
            
            print(f"[{report_num}/{total_reports}] Actor: {actor}")
            print(f"  Status: {color_code}{status}{reset_code}")
            print(f"  Reason: {parsed['reason']}")
            print("-" * 30)
            
            # Save progress immediately
            new_entry = pd.DataFrame([{
                'link': link,
                'status': parsed['value'],
                'reason': parsed['reason']
            }])
            new_entry.to_csv(progress_file, mode='a', header=not os.path.exists(progress_file), index=False)
            processed_links.add(link)

    # Final reconstruction of the validated reports file
    print("\nFinalizing validated reports file...")
    if os.path.exists(progress_file):
        progress_df = pd.read_csv(progress_file)
        passed_links = progress_df[progress_df['status'] == 1]['link'].tolist()
        df_validated = df[df['link'].isin(passed_links)]
        
        os.makedirs(os.path.dirname(os.path.abspath(final_reports)), exist_ok=True)
        df_validated.to_csv(final_reports, sep="\t", index=False)
        print(f"Validation complete. {len(df_validated)}/{total_reports} reports passed.")
        print(f"Validated reports saved to {final_reports}")
    else:
        print("No progress found. Output file was not created.")
