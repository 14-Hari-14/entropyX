import requests
import os
from dotenv import load_dotenv

load_dotenv()

# --- CONFIG ---
API_KEY =   os.environ.get("MALWARE_BAZAAR_API_KEY")
headers = {'Auth-Key': API_KEY.strip()}

# We use a known WannaCry hash just to trigger a successful response
LOCKBIT_HASH = "47c6ba872eea70cf59233fabbdb6d1978cfc7c5602d4710b4f3d123e91f91822"

payload = {
    'query': 'get_info',
    'hash': LOCKBIT_HASH
}

try:
    response = requests.post("https://mb-api.abuse.ch/api/v1/", data=payload, headers=headers)
    
    if response.status_code == 200:
        # The limit info is in the HEADERS, not the JSON body
        print("[+] Connection Successful!")
        print(f"[*] Daily Limit: {response.headers.get('X-Rate-Limit-Limit', 'Not Found')}")
        print(f"[*] Remaining:    {response.headers.get('X-Rate-Limit-Remaining', 'Not Found')}")
        print(f"[*] Reset Time:   {response.headers.get('X-Rate-Limit-Reset', 'Not Found')} (UTC)")
        
        # Also check the body for errors
        data = response.json()
        print(f"[*] API Query Status: {data.get('query_status')}")
    else:
        print(f"[-] HTTP Error {response.status_code}")

except Exception as e:
    print(f"[-] Script Error: {e}")