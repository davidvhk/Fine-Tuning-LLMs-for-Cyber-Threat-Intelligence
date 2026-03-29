import os
import time
import google.generativeai as genai

# Load API Key
api_key = os.environ.get('GOOGLE_API_KEY')
if not api_key:
    try:
        with open('.gemini.key', 'r') as f:
            api_key = f.read().strip()
    except:
        pass

if api_key:
    genai.configure(api_key=api_key)
else:
    print("Error: No Google API Key found.")

# Primary models confirmed available in diagnostic (2026 environment)
MODELS = [
    'models/gemini-2.5-flash', 
    'models/gemini-2.5-pro', 
    'models/gemini-2.0-flash-lite',
    'models/gemini-flash-latest'
]

def bard(text):
    """
    Standard simple call to Gemini API with Daily Quota detection and 4 RPM pacing.
    """
    # 15 seconds sleep allows for exactly 4 calls per minute (stays under 5 RPM for standard free tier)
    time.sleep(15)
    
    for model_name in MODELS:
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(text)
            
            # Check if response actually has text
            if response and hasattr(response, 'text'):
                return response.text
            else:
                # If blocked by safety, return empty string so we don't retry this specific group
                print(f"  Warning: {model_name} blocked the response or returned empty.")
                return ""
                
        except Exception as e:
            err_str = str(e).lower()
            
            # Detect Daily Quota limit or "limit: 0" which often means exhausted
            if "perday" in err_str or "limit: 0" in err_str:
                print(f"  Quota limit (Daily or Zero) reached for {model_name}. Trying next model...")
                continue
            
            # Detect Minute Quota limit (429)
            if "429" in err_str or "quota" in err_str or "exhausted" in err_str:
                print(f"  Minute quota hit for {model_name}. Sleeping 70s to reset...")
                time.sleep(70)
                # Retry once more with the same model after cooldown
                try:
                    model = genai.GenerativeModel(model_name)
                    response = model.generate_content(text)
                    if response and hasattr(response, 'text'):
                        return response.text
                except Exception as retry_e:
                    print(f"  Retry failed for {model_name}: {retry_e}")
                
                continue

            print(f"  Gemini API Error ({model_name}): {e}")
            continue
            
    print("WARNING: All models failed or reached quota. Continuing with current data...")
    return ""
