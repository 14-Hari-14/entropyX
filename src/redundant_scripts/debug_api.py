
import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

# --- CONFIG ---
API_KEY =   os.environ.get("MALWARE_BAZAAR_API_KEY")

def debug_connection():
    url = "https://mb-api.abuse.ch/api/v1/"
    
    # We send both common header names to be 100% safe
    headers = {
        'API-KEY': API_KEY.strip(),
        'Auth-Key': API_KEY.strip()
    }
    
    payload = {'query': 'get_taginfo', 'tag': 'lockbit', 'limit': 1}
    
    print(f"[*] Testing Key (First 5): {API_KEY[:5]}...")
    print(f"[*] Testing Key (Length): {len(API_KEY)} chars")

    try:
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('query_status') == 'ok':
                print("[+ SUCCESS] API Key is valid and working!")
            else:
                print(f"[-] API Key accepted, but Query failed: {data.get('query_status')}")
        elif response.status_code == 401:
            print("[-] ERROR 401: Server explicitly rejected this key.")
            print("    Check if you have 'Verified' your email on abuse.ch.")
        else:
            print(f"[-] HTTP Error {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"[-] Network Error: {e}")

if __name__ == "__main__":
    debug_connection()