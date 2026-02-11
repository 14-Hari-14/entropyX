import subprocess
import os

# --- CONFIG ---
DOWNLOAD_DIR = os.path.normpath(os.path.expanduser("~/Desktop/HardBenign1"))
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# --- THE EXPANDED MANIFEST (250+ IDs) ---
MANIFEST_OLD = [
    # --- BROWSERS & INTERNET (High Entropy Installers) ---
    "Google.Chrome", "Mozilla.Firefox", "Brave.Brave", "Opera.Opera", "Vivaldi.Vivaldi",
    "TorProject.TorBrowser", "Waterfox.Waterfox", "Microsoft.Edge", "Maxthon.Maxthon",
    
    # --- MEDIA & DESIGN (Heavy Resources) ---
    "VideoLAN.VLC", "Audacity.Audacity", "Spotify.Spotify", "Handbrake.Handbrake", 
    "OBSProject.ObsStudio", "GIMP.GIMP", "Inkscape.Inkscape", "Krita.Krita", 
    "BlenderFoundation.Blender", "DigiKam.digiKam", "Adobe.Acrobat.Reader.64-bit",
    "CDBurnerXP.CDBurnerXP", "Kodi.Kodi", "Plex.Plex", "Stremio.Stremio",
    "foobar2000.foobar2000", "MusicBee.MusicBee", "IrfanView.IrfanView",
    
    # --- DEV TOOLS & LANGUAGES (Complex Linker Signatures) ---
    "Microsoft.VisualStudioCode", "Git.Git", "Python.Python.3.12", "NodeJS.NodeJS.LTS", 
    "GoLang.Go", "Rustlang.Rust.MSVC", "Docker.DockerDesktop", "PuTTY.PuTTY", 
    "WinSCP.WinSCP", "FileZilla.FileZilla", "Oracle.JDK.21", "JetBrains.PyCharm.Community",
    "JetBrains.IntelliJIDEA.Community", "Postman.Postman", "Arduino.IDE", 
    "Hashicorp.Vagrant", "Terraform.Terraform", "GitHub.GitHubDesktop", "TortoiseGit.TortoiseGit",
    "DBeaver.DBeaver", "MongoDB.Compass", "HeidiSQL.HeidiSQL", "SQLiteBrowser.SQLiteBrowser",
    
    # --- UTILITIES & SYSTEM (Varying Header Sizes) ---
    "7zip.7zip", "RARLab.WinRAR", "Microsoft.PowerToys", "pbatard.Rufus", "CPUID.CPU-Z",
    "Piriform.CCleaner", "Piriform.Speccy", "BleachBit.BleachBit", "GlarySoft.GlaryUtilities",
    "CrystalDewWorld.CrystalDiskInfo", "CrystalDewWorld.CrystalDiskMark", "CPUID.HWMonitor",
    "BleachBit.BleachBit", "WiseCleaner.WiseDiskCleaner", "IObit.DriverBooster",
    "Sysinternals.ProcessExplorer", "Sysinternals.ProcessMonitor", "Sysinternals.Autoruns",
    "KeePassX.KeePassX", "Bitwarden.Bitwarden", "StandardNotes.StandardNotes",
    
    # --- COMMUNICATION ---
    "Discord.Discord", "SlackTechnologies.Slack", "Telegram.TelegramDesktop", "Zoom.Zoom", 
    "Skype.Skype", "Microsoft.Teams", "Signal.Signal", "Element.Element", "WhatsApp.WhatsApp",

    # --- GAMING & RUNTIMES (Very Large Files) ---
    "Steam.Steam", "EpicGames.EpicGamesLauncher", "GOG.Galaxy", "Ubisoft.Connect",
    "Unity.UnityHub", "EpicGames.UnrealEngine", "Roblox.Roblox",
    
    # --- PRODUCTIVITY ---
    "LibreOffice.LibreOffice", "SumatraPDF.SumatraPDF", "Notepad++.Notepad++", 
    "Evernote.Evernote", "Logitech.Options", "Wacom.Tablet", "AutoHotkey.AutoHotkey",
    "Toggl.TogglDesktop", "AnyDesk.AnyDesk", "TeamViewer.TeamViewer"
    
    # Note: Adding 'Microsoft.DotNet.Runtime.8' and 'Microsoft.DotNet.DesktopRuntime.8'
    # provides many smaller .exe files with modern signatures.
]

MANIFEST = [
    # New additions (diverse, high-yield for EXE installers)
    "Adobe.Acrobat.Reader.32-bit", "Adobe.CreativeCloud", "AdoptOpenJDK.OpenJDK.11", "AdoptOpenJDK.OpenJDK.8",
    "AIMP.AIMP", "Amazon.AWSCLI", "Amazon.Corretto.11", "Amazon.Corretto.17", "Amazon.Corretto.8",
    "Amazon.S3Browser", "Amazon.SamCli", "Anaconda.Anaconda3", "Apache.Maven", "Apache.Tomcat",
    "ApacheDirectoryStudio.ApacheDirectoryStudio", "Avast.FreeAntivirus", "Azure.DataStudio",
    "Balena.Etcher", "Blizzard.Battle.net", "Bitwarden.CLI", "BlenderFoundation.Blender.Benchmark",
    "Canonical.Ubuntu.2004", "Canonical.Ubuntu.2204", "Canonical.Ubuntu.2404", "Cisco.WebexMeetings",
    "Citrix.Workspace", "Clementine.Clementine", "Codeblocks.Codeblocks", "Corsair.iCUE.4",
    "Corsair.iCUE.5", "DBBrowserForSQLite.DBBrowserForSQLite", "Devolutions.RemoteDesktopManagerFree",
    "DotPDN.PaintDotNet", "EclipseAdoptium.Temurin.11", "EclipseAdoptium.Temurin.17", "EclipseAdoptium.Temurin.8",
    "EclipseFoundation.Eclipse", "ElectronicArts.EADesktop", "Foxit.FoxitPDFEditor", "Foxit.FoxitPDFReader",
    "FreeCAD.FreeCAD", "FreeDownloadManager.FDM", "GnuPG.Gpg4win", "Google.AndroidStudio",
    "Google.Chrome.Beta", "Google.Chrome.Dev", "Google.Drive", "Google.EarthPro",
    "Greenshot.Greenshot", "HandBrake.HandBrake.CLI", "Hashicorp.VirtualBox.ExtensionPack",
    "IBM.Semeru.11", "IBM.Semeru.17", "IBM.Semeru.8", "IDM.InternetDownloadManager",
    "ImageMagick.ImageMagick", "JetBrains.CLion", "JetBrains.DataGrip", "JetBrains.GoLand",
    "JetBrains.PhpStorm", "JetBrains.Rider", "JetBrains.RubyMine", "JetBrains.WebStorm",
    "KeePassXCTeam.KeePassXC", "Kitware.CMake", "Kubernetes.minikube", "Logitech.GHUB",
    "Logitech.LogiTune", "Logitech.UnifyingSoftware", "MPC-BE.MPC-BE", "Malwarebytes.Malwarebytes",
    "Mega.MEGASync", "Microsoft.AzureCLI", "Microsoft.AzureCosmosEmulator", "Microsoft.AzureFunctionsCoreTools",
    "Microsoft.AzureStorageEmulator", "Microsoft.AzureStorageExplorer", "Microsoft.Bicep",
    "Microsoft.BotFrameworkComposer", "Microsoft.BotFrameworkEmulator", "Microsoft.DotNet.SDK.3",
    "Microsoft.DotNet.SDK.5", "Microsoft.DotNet.SDK.6", "Microsoft.DotNet.SDK.7", "Microsoft.DotNet.SDK.8",
    "Microsoft.DotNet.SDK.Preview", "Microsoft.OneDrive", "Microsoft.PowerBI", "Microsoft.PowerShell",
    "Microsoft.PowerShell.Preview", "Microsoft.RemoteDesktopClient", "Microsoft.SQLServerManagementStudio",
    "Microsoft.VisualStudio.2022.BuildTools", "Microsoft.VisualStudio.2022.Community",
    "Microsoft.VisualStudio.2022.Enterprise", "Microsoft.VisualStudio.2022.Professional",
    "Microsoft.VisualStudio.Locator", "Microsoft.VisualStudioCode.Insiders", "Microsoft.WindowsSDK",
    "Microsoft.WindowsTerminal.Preview", "Microsoft.WingetCreate", "Microsoft.XNARedist",
    "Mozilla.Thunderbird", "NZXT.CAM", "Nasm.Nasm", "Nextcloud.NextcloudDesktop",
    "Notion.Notion", "OBSProject.OBSStudio.Pre-release", "Obsidian.Obsidian",
    "OpenJS.NodeJS.Nightly", "OpenVPNTechnologies.OpenVPN", "OpenVPNTechnologies.OpenVPNConnect",
    "Oracle.JavaRuntimeEnvironment", "Oracle.MySQLWorkbench", "Oracle.VirtualBox.ExtensionPack",
    "Pandoc.Pandoc", "Parsec.Parsec", "Piriform.Defraggler", "Piriform.Recuva",
    "Plex.PlexMediaPlayer", "Plex.PlexMediaServer", "Postman.Postman.Canary",
    "PrivateInternetAccess.PrivateInternetAccess", "ProtonTechnologies.ProtonVPN", "Python.Python.3.10",
    "Python.Python.3.11", "Python.Python.3.9", "qBittorrent.qBittorrent", "Razer.Synapse3",
    "RealVNC.VNCViewer", "RevoGroup.RevoUninstaller", "RevoGroup.RevoUninstallerPro",
    "SCOOTERSoftware.BeyondCompare4", "SQLite.SQLite", "SublimeHQ.SublimeText.3",
    "SublimeHQ.SublimeText.4", "SublimeHQ.SublimeText.Dev", "Symless.Synergy",
    "TailwindLabs.TailwindCSS", "TechSmith.Snagit", "TeraCopy.TeraCopy",
    "TheDocumentFoundation.LibreOffice", "Valve.SteamCMD", "Vercel.Hyper",
    "VideoLAN.VLC.Nightly", "VMware.HorizonClient", "VMware.WorkstationPro",
    "VeraCrypt.VeraCrypt", "Wagnardsoft.DisplayDriverUninstaller", "WiresharkFoundation.Wireshark",
    "XnSoft.XnView", "Yarn.Yarn", "balena.balenaCLI", "dbgate.dbgate",
    "eclipse.embed-cdt", "gitextensions.gitextensions", "jqlang.jq", "kubernetes-cli",
    "msys2.msys2", "obsidianmd.obsidian-insider", "openscad.openscad", "portSwigger.burp.suite.community",
    "radareorg.cutter", "rustdesk.rustdesk", "samsung.magician", "seafile.seafile-client",
    "shininglight.openssl", "sqlitebrowser.sqlitebrowser", "strawberryperl.strawberryperl",
    "sublimetext.sublime-merge", "tailwindlabs.tailwindcss", "telerik.fiddler.classic",
    "temurin.temurin.18", "typora.typora", "ventoy.ventoy", "voidtools.Everything",
    "whatsapp.whatsapp.beta", "winmerge.winmerge", "xnsoft.xnconvert", "xnsoft.xnviewmp",
    "yubico.yubikey-manager", "zotero.zotero"
]

def run_harvest():
    success_count = 0
    total = len(MANIFEST)
    print(f"[*] Attempting to fetch {total} packages...")

    for i, pkg_id in enumerate(MANIFEST):
        print(f"[{i+1}/{total}] Fetching: {pkg_id}")
        
        cmd = [
            "winget", "download", "--id", pkg_id,
            "--download-directory", DOWNLOAD_DIR,
            "--accept-source-agreements",
            "--accept-package-agreements"
        ]
        
        try:
            # Skipping output to keep terminal clean
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0:
                success_count += 1
            else:
                print(f"    [!] Skip: {pkg_id} (Package unavailable or Store-only)")
        except:
            continue

    print(f"\n[FINISH] Success: {success_count} installers saved to {DOWNLOAD_DIR}")

if __name__ == "__main__":
    run_harvest()