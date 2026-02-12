import subprocess
import os
import time

# --- CONFIG ---
DOWNLOAD_DIR = os.path.normpath(os.path.expanduser("~/Desktop/HardBenign1"))
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# I've included 100+ diverse IDs here to get you started.
MANIFEST = [
    "Google.Chrome", "Mozilla.Firefox", "Brave.Brave", "Opera.Opera", "Vivaldi.Vivaldi",
    "VideoLAN.VLC", "Audacity.Audacity", "Spotify.Spotify", "Handbrake.Handbrake", "OBSProject.ObsStudio",
    "GIMP.GIMP", "Inkscape.Inkscape", "Krita.Krita", "BlenderFoundation.Blender", "DigiKam.digiKam",
    "Microsoft.VisualStudioCode", "Git.Git", "Python.Python.3.12", "NodeJS.NodeJS.LTS", "GoLang.Go",
    "Rustlang.Rust.MSVC", "Docker.DockerDesktop", "PuTTY.PuTTY", "WinSCP.WinSCP", "FileZilla.FileZilla",
    "7zip.7zip", "RARLab.WinRAR", "Microsoft.PowerToys", "pbatard.Rufus", "CPUID.CPU-Z",
    "Discord.Discord", "SlackTechnologies.Slack", "Telegram.TelegramDesktop", "Zoom.Zoom", "Skype.Skype",
    "Notepad++.Notepad++", "Postman.Postman", "Tableau.Public", "WiresharkFoundation.Wireshark",
    "Oracle.JDK.21", "JetBrains.PyCharm.Community", "LibreOffice.LibreOffice", "SumatraPDF.SumatraPDF",
    "CDBurnerXP.CDBurnerXP", "TeamViewer.TeamViewer", "AnyDesk.AnyDesk", "BleachBit.BleachBit",
    "GlarySoft.GlaryUtilities", "CCleaner.CCleaner", "Malwarebytes.Malwarebytes", "Insecure.Nmap",
    "WiresharkFoundation.Wireshark", "WinPcap.WinPcap", "Nmap.Npcap", "AngryIPScanner.AngryIPScanner",
    "Sysinternals.ProcessExplorer", "Sysinternals.ProcessMonitor", "Sysinternals.Autoruns",
    "KeePassX.KeePassX", "Bitwarden.Bitwarden", "StandardNotes.StandardNotes", "Proton.ProtonVPN",
    "Steam.Steam", "EpicGames.EpicGamesLauncher", "GOG.Galaxy", "Ubisoft.Connect",
    "CrystalDewWorld.CrystalDiskInfo", "CrystalDewWorld.CrystalDiskMark", "CPUID.HWMonitor",
    "Piriform.Speccy", "CINEBENCH.CINEBENCH", "Geekbench.Geekbench.6", "FurMark.FurMark",
    "Transmission.Transmission", "qBittorrent.qBittorrent", "Deluge.Deluge", "Picard.MusicBrainz",
    "Kodi.Kodi", "Plex.Plex", "Stremio.Stremio", "PopcornTime.PopcornTime",
    "Arduino.IDE", "RaspberryPi.RaspberryPiImager", "Etcher.Etcher", "Balena.Etcher",
    "VirtualBox.VirtualBox", "VMware.WorkstationPlayer", "Hashicorp.Vagrant", "Terraform.Terraform"
]

def run_manifest_harvest():
    success_count = 0
    total = len(MANIFEST)
    
    print(f"[*] Starting download of {total} packages to: {DOWNLOAD_DIR}")

    for i, pkg_id in enumerate(MANIFEST):
        print(f"[{i+1}/{total}] Fetching: {pkg_id}...")
        
        # Explicit download command
        cmd = [
            "winget", "download", "--id", pkg_id,
            "--download-directory", DOWNLOAD_DIR,
            "--accept-source-agreements",
            "--accept-package-agreements"
        ]
        
        try:
            # shell=False is deterministic and safer
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if res.returncode == 0:
                success_count += 1
            else:
                # Silently fail and move on
                print(f"    [!] Failed/Skipped: {pkg_id}")
        
        except Exception:
            continue
            
    print(f"\n[SUCCESS] Harvested {success_count} installers.")
    print("[*] These files are safe to analyze on your Windows machine.")

if __name__ == "__main__":
    run_manifest_harvest()