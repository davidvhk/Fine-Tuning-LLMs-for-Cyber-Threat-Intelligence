import os
import time
import requests
import json

# Ollama Configuration
OLLAMA_URL = "http://ollama.vhkzone.org:11434/api/generate"
OLLAMA_MODEL = "phi4-mini:latest"

def ollama_generate(text):
    """
    Main interface for the Ollama server.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": text,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        response.raise_for_status()
        
        result = response.json()
        return result.get("response", "")
        
    except Exception as e:
        print(f"  Ollama API Error: {e}")
        return ""

# Compatibility aliases
def bard(text):
    return ollama_generate(text)

def ollama_bard(text):
    return ollama_generate(text)
