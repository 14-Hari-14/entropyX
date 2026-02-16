import subprocess
import os
import time  # optional: small delay to be nice to servers

# --- CONFIG ---
DOWNLOAD_DIR = os.path.normpath(os.path.expanduser("~/Desktop/HardBenign"))  # or HardBenign if that's your folder
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# Combined & expanded manifest – old kept, new ~120 added (focus on .exe/.msi heavy)
OLD_MANIFEST = [
    # Your original core ones (kept for completeness, winget skips if present)
    "Google.Chrome", "Mozilla.Firefox", "Brave.Brave", "Opera.Opera", "Vivaldi.Vivaldi",
    "TorProject.TorBrowser", "Waterfox.Waterfox", "Microsoft.Edge",
    "VideoLAN.VLC", "Audacity.Audacity", "Spotify.Spotify", "Handbrake.Handbrake",
    "OBSProject.ObsStudio", "GIMP.GIMP", "Inkscape.Inkscape", "Krita.Krita",
    "BlenderFoundation.Blender", "Adobe.Acrobat.Reader.64-bit",
    "Microsoft.VisualStudioCode", "Git.Git", "Python.Python.3.12", "NodeJS.NodeJS.LTS",
    "Docker.DockerDesktop", "PuTTY.PuTTY", "WinSCP.WinSCP", "FileZilla.FileZilla",
    "JetBrains.PyCharm.Community", "JetBrains.IntelliJIDEA.Community", "Postman.Postman",
    "7zip.7zip", "RARLab.WinRAR", "Microsoft.PowerToys", "pbatard.Rufus", "CPUID.CPU-Z",
    "Piriform.CCleaner", "BleachBit.BleachBit", "CrystalDewWorld.CrystalDiskInfo",
    "Discord.Discord", "SlackTechnologies.Slack", "Telegram.TelegramDesktop", "Zoom.Zoom",
    "Steam.Steam", "EpicGames.EpicGamesLauncher", "LibreOffice.LibreOffice", "Notepad++.Notepad++",
    "AnyDesk.AnyDesk", "TeamViewer.TeamViewer",

    # Previous additions you already had (kept, skips fast)
    "Adobe.Acrobat.Reader.32-bit", "Anaconda.Anaconda3", "Balena.Etcher", "Bitwarden.Bitwarden",
    "Citrix.Workspace", "Codeblocks.Codeblocks", "DotPDN.PaintDotNet", "EclipseAdoptium.Temurin.11",
    "EclipseAdoptium.Temurin.17", "EclipseAdoptium.Temurin.8", "Foxit.FoxitPDFEditor",
    "FreeCAD.FreeCAD", "Google.AndroidStudio", "Greenshot.Greenshot", "ImageMagick.ImageMagick",
    "KeePassXCTeam.KeePassXC", "Kubernetes.minikube", "Malwarebytes.Malwarebytes",
    "Microsoft.DotNet.SDK.8", "Microsoft.PowerShell", "Microsoft.SQLServerManagementStudio",
    "Microsoft.VisualStudio.2022.BuildTools", "Mozilla.Thunderbird", "Notion.Notion",
    "Obsidian.Obsidian", "qBittorrent.qBittorrent", "VeraCrypt.VeraCrypt",
    "VMware.WorkstationPro", "WiresharkFoundation.Wireshark", "Zotero.Zotero",

    # NEW ~120 high-yield additions (diverse categories, likely .exe/.msi in 2026)
    "Amazon.AWSCLI", "Arduino.ArduinoIDE", "AutoHotkey.AutoHotkey", "BeyondCompare.BeyondCompare",
    "CMake.CMake", "DBeaver.DBeaver", "Everything.VoidTools", "Fiddler.Everywhere",
    "FileZilla.FileZilla.Server", "Ghisler.TotalCommander", "GitExtensions.GitExtensions",
    "Google.EarthPro", "HashiCorp.Vagrant", "HeidiSQL.HeidiSQL", "Hugo.Hugo.Extended",
    "Insomnia.Insomnia", "IrfanView.IrfanView", "JetBrains.CLion", "JetBrains.DataGrip",
    "JetBrains.GoLand", "JetBrains.PhpStorm", "JetBrains.Rider", "JetBrains.RubyMine",
    "JetBrains.WebStorm", "KDE.Okular", "Lenovo.Vantage", "Logitech.OptionsPlus",
    "Microsoft.AzureDataStudio", "Microsoft.Bicep", "Microsoft.PowerToys", "Microsoft.Sysinternals.Autoruns",
    "Microsoft.Sysinternals.ProcessExplorer", "Microsoft.Sysinternals.ProcessMonitor",
    "Microsoft.WindowsTerminal", "MiniTool.PartitionWizard.Free", "MPC-HC.MPC-HC",
    "Neovim.Neovim", "Nmap.Nmap", "Notion.Notion", "OhMyPosh.OhMyPosh",
    "OpenSCAD.OpenSCAD", "Oracle.VirtualBox", "PDF24.PDF24Creator", "PaintDotNet.PaintDotNet",
    "Pandoc.Pandoc", "PortSwigger.BurpSuite.Community", "PowerShell.PowerShell",
    "PrivateInternetAccess.PrivateInternetAccess", "Proton.ProtonVPN", "PuTTY.PuTTYgen",
    "Python.Launcher", "RadareOrg.Cutter", "RealVNC.VNCViewer", "Recuva.Recuva",
    "Rufus.Rufus", "Rustlang.Rustup", "Samsung.Magician", "SublimeHQ.SublimeMerge",
    "SublimeHQ.SublimeText.4", "Sysinternals.Autoruns", "Sysinternals.BgInfo",
    "Sysinternals.DiskView", "Sysinternals.TCPView", "TablePlus.TablePlus",
    "TechPowerUp.GPU-Z", "TeraCopy.TeraCopy", "Typora.Typora", "Ventoy.Ventoy",
    "VisualStudioCode.VisualStudioCode.Insiders", "VoidTools.Everything",
    "WinDirStat.WinDirStat", "WinMerge.WinMerge", "WinSCP.WinSCP", "XnView.XnView",
    "Yarn.Yarn", "Zadig.Zadig", "balena.balenaEtcher", "dbeaver.dbeaver",
    "drawio.drawio", "fastfetch.fastfetch", "freetube.Freetube", "golang.go",
    "he3.app", "httpie.desktop", "hugo.extended", "insomnia.Insomnia",
    "ionic.ionic", "jupyterlab-desktop.jupyterlab-desktop", "keepassxc.keepassxc",
    "lazycat.lazycat", "lens.lens", "lunarclient.lunarclient", "mremoteng.mremoteng",
    "neovide.neovide", "netbirdio.netbird", "ngrok.ngrok", "nvm.nvm",
    "ollama.ollama", "openlens.openlens", "orbstack.orbstack", "picpick.picpick",
    "postman.postman-agent", "rclone.rclone", "redis.redis", "restic.restic",
    "rclone.rclone", "rustdesk.rustdesk", "starship.starship", "syncthing.syncthing",
    "tailscale.tailscale", "tldr.tldr", "vagrant.vagrant", "vscodium.vscodium",
    "wez.wezterm", "wingetcreate", "yt-dlp.yt-dlp", "zig.zig", "zoxide.zoxide",
        # Dev & Tools
    "JetBrains.CLion",
    "JetBrains.DataGrip",
    "JetBrains.GoLand",
    "JetBrains.PhpStorm",
    "JetBrains.Rider",
    "JetBrains.RubyMine",
    "JetBrains.WebStorm",
    "JetBrains.Toolbox",
    "SublimeHQ.SublimeText.4",
    "SublimeHQ.SublimeMerge",
    "Neovim.Neovim",
    "VisualStudioCode.VisualStudioCode.Insiders",
    "vscodium.vscodium",
    "wez.wezterm",

    # Utilities & System
    "Ghisler.TotalCommander",
    "WinDirStat.WinDirStat",
    "TechPowerUp.GPU-Z",
    "MiniTool.PartitionWizard.Free",
    "PDF24.PDF24Creator",
    "Typora.Typora",
    "drawio.drawio",
    "picpick.picpick",

    # Security & VPN
    "Proton.ProtonVPN",
    "NordVPN.NordVPN",
    "Surfshark.Surfshark",
    "ExpressVPN.ExpressVPN",
    "PrivateInternetAccess.PrivateInternetAccess",
    "CyberGhost.CyberGhostVPN",

    # Networking & Misc
    "tailscale.tailscale",
    "netbirdio.netbird",
    "ngrok.ngrok",
    "rclone.rclone",
    "syncthing.syncthing",
    "rustdesk.rustdesk",
    "Nmap.Nmap",
    "WiresharkFoundation.Wireshark",          # different version likely
    "OpenVPNTechnologies.OpenVPNConnect",

    # Creative & Media
    "Wondershare.Filmora",
    "DaVinciResolve.DaVinciResolve",
    "Affinity.Designer",
    "Affinity.Photo",
    "Affinity.Publisher",

    # Other high-entropy .exe candidates
    "CMake.CMake",
    "Everything.VoidTools",
    "Fiddler.Everywhere",
    "Hugo.Hugo.Extended",
    "Insomnia.Insomnia",
    "OhMyPosh.OhMyPosh",
    "OpenSCAD.OpenSCAD",
    "Ventoy.Ventoy",
    "Zadig.Zadig",
    "starship.starship",
    "zoxide.zoxide",
    "fastfetch.fastfetch",
    "lazycat.lazycat",
    "tldr.tldr",
    "yt-dlp.yt-dlp",
    "zig.zig",
]

MANIFEST = [
    # More JetBrains (different editions/variants not in your list)
    "JetBrains.Aqua",
    "JetBrains.Datalore",
    "JetBrains.Fleet",
    "JetBrains.MPS",

    # Editors & IDE alternatives
    "Helix.Helix",
    "Lapce.Lapce",
    "Zed.Zed",

    # File / System Utils
    "JAMSoftware.TreeSize.Free",
    "AntibodySoftware.Antibody",
    "BulkRenameUtility.BulkRenameUtility",
    "Files.Files",
    "ShareX.ShareX",

    # Security / Privacy / VPN extras
    "MullvadVPN.MullvadVPN",
    "Windscribe.Windscribe",
    "Bitwarden.CLI",
    "Yubico.YubiKeyManager",

    # Media / Creative
    "Kdenlive.Kdenlive",
    "Shotcut.Shotcut",
    "OliveTeam.Olive",
    "Natron.Natron",

    # Dev / CLI / Portable tools
    " Nushell.Nushell",
    "Eza-ls.Eza",
    "Bat.Bat",
    "Fd.Fd",
    "Ripgrep.Ripgrep",
    "Tokei.Tokei",
    "Hexyl.Hexyl",
    "Tokei.Tokei",

    # Other high-entropy .exe heavy
    "BleachBit.BleachBit",          # different version likely
    "SumatraPDF.SumatraPDF",
    "qBittorrent.qBittorrent",
    "Calibre.Calibre",
    "JDownloader.JDownloader",
    "yt-dlp.yt-dlp",                 # new version if available
    "yt-dlp.YtDlp",
    "yt-dlp.YtDlp-nightly",
    "Ventoy.Ventoy",                 # retry if missed
    "Rufus.Rufus",
    "Etcher.BalenaEtcher",
    "GodotEngine.GodotEngine",
    "GodotEngine.GodotMono",
    "Blender.Benchmark",
    "LMMS.LMMS",
    "TuxGuitar.TuxGuitar",
    "MuseScore.MuseScore",
    "Avidemux.Avidemux",
    "LosslessCut.LosslessCut",
    "HandBrake.HandBrake.Nightly",
    "MPC-BE.MPC-BE",
    "SMPlayer.SMPlayer",
    "VLC.VLC.Nightly",
    "Inkscape.Inkscape",
    "Krita.Krita.Beta",
    "GnuCash.GnuCash",
    "MoneyManagerEx.MoneyManagerEx",
    "HomeBank.HomeBank",
    "Stellarium.Stellarium",
    "Marble.Marble",
    "Celestia.Celestia"
]

def run_harvest():
    success_count = 0
    total = len(MANIFEST)
    print(f"[*] Attempting to fetch/check {total} packages...")
    for i, pkg_id in enumerate(MANIFEST):
        print(f"[{i+1}/{total}] Processing: {pkg_id}")
        cmd = [
            "winget", "download", "--id", pkg_id,
            "--download-directory", DOWNLOAD_DIR,
            "--accept-source-agreements",
            "--accept-package-agreements"
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)  # increased timeout for large files
            if res.returncode == 0:
                success_count += 1
                print(f"   [+] Success: {pkg_id}")
            else:
                print(f"   [!] Skip/Fail: {pkg_id} (code {res.returncode})")
            time.sleep(1)  # gentle rate limit
        except subprocess.TimeoutExpired:
            print(f"   [!] Timeout: {pkg_id} – consider manual download later")
        except Exception as e:
            print(f"   [!] Error: {pkg_id} → {e}")
    print(f"\n[FINISH] New successes this run: {success_count}")
    print(f"Check folder for total (should exceed 200 now).")

if __name__ == "__main__":
    run_harvest()