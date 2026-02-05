# --- CONFIGURATION ---
# The path from your screenshot:
$dest = "\\tsclient\_home_hari_Computer_Science_projects_entropyX_data_benign" 
$count = 400

# --- THE SCRIPT ---
Write-Host "Scanning System32 for random EXE and DLL files..." -ForegroundColor Cyan

# 1. Get list of files
$files = Get-ChildItem -Path "C:\Windows\System32" -Include *.exe, *.dll -Recurse -ErrorAction SilentlyContinue

# 2. Pick 400 random ones
$randomFiles = $files | Get-Random -Count $count

# 3. Copy them to your Linux folder
$i = 0
foreach ($file in $randomFiles) {
    $i++
    Write-Progress -Activity "Transferring to Linux..." -Status "Copying $($file.Name)" -PercentComplete (($i / $count) * 100)
    
    try {
        Copy-Item -Path $file.FullName -Destination $dest -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Skipped $($file.Name) (Permission Denied)"
    }
}

Write-Host "Done! Copied $i files to Linux." -ForegroundColor Green