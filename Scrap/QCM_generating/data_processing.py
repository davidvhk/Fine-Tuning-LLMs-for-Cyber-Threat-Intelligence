import csv
import random
import pandas as pd
import json
import os

def take_random_rows(input_csv, num_rows, output_csv=None):
    """
    Take a specified number of random rows from an input CSV file and return them as a DataFrame.
    Optionally saves the selected rows to an output CSV file.

    Parameters:
    - input_csv (str): The path to the input CSV file.
    - num_rows (int): The number of random rows to select.
    - output_csv (str): Optional path to save the selected rows.

    Returns:
    - pd.DataFrame: The selected random rows.
    """
    if not os.path.exists(input_csv):
        print(f"Error: {input_csv} does not exist.")
        return pd.DataFrame()

    df = pd.read_csv(input_csv)
    
    if len(df) <= num_rows:
        print(f"Input file has only {len(df)} rows, which is less than or equal to the requested {num_rows} rows.")
        selected_df = df
    else:
        selected_df = df.sample(n=num_rows, random_state=42)

    if output_csv:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        selected_df.to_csv(output_csv, index=False)
        print(f"Saved {len(selected_df)} random rows to {output_csv}")

    return selected_df

def sanitize_tsv_value(value):
    if isinstance(value, str):
        # Replace tabs with spaces
        value = value.replace('\t', ' ')
        # Replace newlines with spaces
        value = value.replace('\n', ' ').replace('\r', ' ')
    return value

def qcm_json_to_tsv(json_file_path, tsv_filename):
    if not os.path.exists(json_file_path):
        print(f"Error: {json_file_path} not found.")
        return

    with open(json_file_path, 'r', encoding='utf-8') as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            print(f"Error: {json_file_path} is not a valid JSON file.")
            return

    with open(tsv_filename, 'w', newline='', encoding='utf-8') as tsv_file:
        writer = csv.writer(tsv_file, delimiter='\t')
        # Write header row
        writer.writerow(['Reference', 'Question', 'Option A', 'Option B', 'Option C', 'Option D', 'Prompt', 'GT', 'Explanation'])

        for obj in data:
            # Basic mapping, might need adjustment based on Gemini's exact output format
            ref = obj.get('CVE_ID', obj.get('CWE_ID', obj.get('CAPEC_ID', 'N/A')))
            question = sanitize_tsv_value(obj.get('Question', ''))
            options = obj.get('Options', {})
            opt_a = sanitize_tsv_value(options.get('A', ''))
            opt_b = sanitize_tsv_value(options.get('B', ''))
            opt_c = sanitize_tsv_value(options.get('C', ''))
            opt_d = sanitize_tsv_value(options.get('D', ''))
            correct = obj.get('Correct Answer', '')
            explanation = sanitize_tsv_value(obj.get('Explanation', ''))
            
            prompt = f"Question: {question}\nA) {opt_a}\nB) {opt_b}\nC) {opt_c}\nD) {opt_d}\nAnswer:"
            
            writer.writerow([ref, question, opt_a, opt_b, opt_c, opt_d, prompt, correct, explanation])
    print(f"Converted {len(data)} JSON MCQs to {tsv_filename}")
