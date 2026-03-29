import pandas as pd
import os

def preprocess_cti_data_to_llm(cti_rcm_path, cti_vsp_path, cti_mcq_path, cti_tta_path):
    def safe_read(path):
        if os.path.exists(path):
            try:
                return pd.read_csv(path)
            except:
                return pd.DataFrame()
        return pd.DataFrame()

    # Read the CSV files
    cti_rcm = safe_read(cti_rcm_path)
    cti_vsp = safe_read(cti_vsp_path)
    cti_mcq = safe_read(cti_mcq_path)
    cti_tta = safe_read(cti_tta_path)

    # Define prompt templates
    cti_tta_prompt_template = ("You are given a threat report that describes a cyber incident. Any direct mentions of "
                               "the threat actor group, specific campaign names, or malware names responsible have been "
                               "replaced with [PLACEHOLDER]. Your task is to analyze the report and attribute the incident "
                               "to a known threat actor based on the techniques, tactics, procedures (TTPs), and any other "
                               "relevant information described. Please provide the name of the threat actor you believe is "
                               "responsible and briefly explain your reasoning. Threat Report: {Text}")
    
    cti_vsp_prompt_template = ("Analyze the following CVE description and calculate the CVSS v3.1 Base Score. Determine the "
                               "values for each base metric: AV, AC, PR, UI, S, C, I, and A. Summarize each metric's value and "
                               "provide the final CVSS v3.1 vector string. Ensure the final line of your response contains only "
                               "the CVSS v3 Vector String in the following format: Example format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                               "S:U/C:H/I:H/A:H CVE Description: {Description}")
    
    cti_rcm_prompt_template = ("Analyze the following CVE description and map it to the appropriate CWE. Provide a brief "
                               "justification for your choice. Ensure the last line of your response contains only the CWE ID. "
                               "CVE Description: {Description}")
    
    cti_mcq_prompt_template = ("You are given a multiple-choice question (MCQ) from a Cyber Threat Intelligence (CTI) knowledge "
                               "benchmark dataset. Your task is to choose the best option among the four provided. Return your "
                               "answer as a single uppercase letter: A, B, C, or D. **Question:** {question} ? **Options:** "
                               "A) {option_a} B) {option_b} C) {option_c} D) {option_d} **Important:** The last line of your "
                               "answer should contain only the single letter corresponding to the best option, with no additional text.")
    
    final_dfs = []

    # Apply the prompts to each dataframe if it's not empty and has required columns
    if not cti_tta.empty and 'Text' in cti_tta.columns and 'GT' in cti_tta.columns:
        cti_tta['Prompt'] = cti_tta['Text'].apply(lambda text: cti_tta_prompt_template.format(Text=text))
        final_dfs.append(cti_tta[['Prompt', 'GT']])

    if not cti_vsp.empty and 'Description' in cti_vsp.columns and 'GT' in cti_vsp.columns:
        cti_vsp['Prompt'] = cti_vsp['Description'].apply(lambda desc: cti_vsp_prompt_template.format(Description=desc))
        final_dfs.append(cti_vsp[['Prompt', 'GT']])

    if not cti_rcm.empty and 'Description' in cti_rcm.columns and 'GT' in cti_rcm.columns:
        cti_rcm['Prompt'] = cti_rcm['Description'].apply(lambda desc: cti_rcm_prompt_template.format(Description=desc))
        final_dfs.append(cti_rcm[['Prompt', 'GT']])

    if not cti_mcq.empty and all(col in cti_mcq.columns for col in ['Question', 'Option A', 'Option B', 'Option C', 'Option D', 'GT']):
        cti_mcq['Prompt'] = cti_mcq.apply(lambda row: cti_mcq_prompt_template.format(
            question=row['Question'],
            option_a=row['Option A'],
            option_b=row['Option B'],
            option_c=row['Option C'],
            option_d=row['Option D']
        ), axis=1)
        final_dfs.append(cti_mcq[['Prompt', 'GT']])

    if not final_dfs:
        print("Warning: No valid training data could be preprocessed.")
        return pd.DataFrame(columns=['Prompt', 'GT'])

    # Concatenate all valid dataframes into the final training DataFrame
    training_df = pd.concat(final_dfs, ignore_index=True)

    return training_df
