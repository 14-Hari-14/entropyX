import subprocess
import os
import time

# --- CONFIG ---
DOWNLOAD_DIR = os.path.normpath(os.path.expanduser("~/Desktop/HardBenign"))
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# A curated list of "Hard" Benign IDs (High entropy, complex PE structures)
HARD_IDS = [
    "Google.Chrome", "VideoLAN.VLC", "Mozilla.Firefox", "Microsoft.VisualStudioCode",
    "Git.Git", "Python.Python.3.12", "7zip.7zip", "Notepad++.Notepad++",
    "GIMP.GIMP", "Inkscape.Inkscape", "Audacity.Audacity", "Discord.Discord",
    "Spotify.Spotify", "Oracle.JDK.21", "NodeJS.NodeJS.LTS", "Docker.DockerDesktop",
    "Brave.Brave", "Tableau.Public", "WiresharkFoundation.Wireshark"
]

def fetch_samples():
    success_count = 0
    print(f"[*] Destination: {DOWNLOAD_DIR}")
    print(f"[*] Attempting to fetch {len(HARD_IDS)} complex benign installers...")

    for pkg_id in HARD_IDS:
        print(f"    [>] Downloading: {pkg_id}...", end="\r")
        
        # --accept-source-agreements and --accept-package-agreements are CRITICAL
        # for non-interactive scripts.
        cmd = [
            "winget", "download", 
            "--id", pkg_id, 
            "--download-directory", DOWNLOAD_DIR,
            "--accept-source-agreements",
            "--accept-package-agreements"
        ]
        
        try:
            # shell=False is safer for Windows to avoid escaping issues
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                success_count += 1
                print(f"    [OK] Saved: {pkg_id}             ")
            else:
                # Often fails if the package only has an MSIX version (Store apps)
                print(f"    [!] Skipped: {pkg_id} (No direct EXE/MSI download)")
                
        except Exception as e:
            print(f"    [ERROR] {pkg_id}: {str(e)[:50]}")
        
        time.sleep(1) # Minimize CDN throttling

    print(f"\n[FINISH] Successfully collected {success_count} installers.")
    print("[*] Next Step: Run your extractor.py on the folder above.")

if __name__ == "__main__":
    fetch_samples()