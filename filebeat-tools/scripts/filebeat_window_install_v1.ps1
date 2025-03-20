### Progressba hide option
$OriginalPref = $ProgressPreference # Default is 'Continue'
$ProgressPreference = "SilentlyContinue"


Write-Host -ForegroundColor green "============================"
Write-Host -ForegroundColor green "Install winlogbeat for ELK."
Write-Host -ForegroundColor green "============================"

#######################################################
Write-Host "1. Add host : " -NoNewline
$HOST_FILE = 'C:\Windows\System32\drivers\etc\hosts'
$HOST_FILE_CONTENTS = @"

################################
192.168.1.1    elk
"@

if (Get-Content $HOST_FILE |Select-String "elk" -Quiet) {
    Write-Host -ForegroundColor green "=>[SKIP] Already Setting"
} else {
    Write-Host -ForegroundColor blue -BackgroundColor white "=> [OK]"
    Add-Content -Path $HOST_FILE -Value $HOST_FILE_CONTENTS
}

#######################################################
Write-Host "2-1. Download winlogbeat : " -NoNewline
$PKG_URL = 'http://192.168.1.1/winlogbeat/windows2019'
$PKG_FILE = 'winlogbeat-8.12.1-windows-x86_64'
$PKG_INSTALL_FILE = 'winlogbeat-8.12.1'
$DOWNLOAD_PATH = 'C:\Users\administrator\Downloads'

# $PKG_FILE_EXISTS = [System.IO.File]::Exists("C:\Users\administrator\Downloads\winlogbeat-8.12.1-windows-x86_64")
$PKG_INSTALL_EXISTS = [System.IO.File]::Exists("C:\Program Files\$PKG_INSTALL_FILE")

if (Test-Path $DOWNLOAD_PATH\$PKG_FILE) {
    Remove-Item  -Recurse -Force -Confirm:$false -Path $DOWNLOAD_PATH\$PKG_FILE
    Remove-Item  -Recurse -Force -Confirm:$false -Path $DOWNLOAD_PATH\$PKG_FILE
}

if (-Not (Test-Path "C:\Program Files\$PKG_INSTALL_FILE")) {
# if (Test-Path "C:\Users\administrator\Downloads\$PKG_INSTALL_FILE") {
    Invoke-WebRequest -Uri $PKG_URL/$PKG_FILE.zip -OutFile $DOWNLOAD_PATH\$PKG_FILE.zip
    Write-Host -ForegroundColor blue -BackgroundColor white "=> [OK] Download winlogebeat"

    Write-Host "2-2. Install winlogbeat : " -NoNewline
    cd $DOWNLOAD_PATH
    Expand-Archive .\$PKG_FILE.zip -DestinationPath .\
    Rename-Item -Path .\$PKG_FILE  -NewName $PKG_INSTALL_FILE
    Move-Item -Path .\$PKG_INSTALL_FILE -Destination "C:\Program Files\" -Force

    if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor Magenta "=>[WARR] Already created winlogbet.service so, re-create winlogbeat.service"
        sc.exe delete winlogbeat |Out-Null
    } else {
        New-Service -name winlogbeat `
        -displayName Winlogbeat `
        -binaryPathName "`"C:\Program Files\$PKG_INSTALL_FILE\winlogbeat.exe`" --environment=windows_service -c `"C:\Program Files\$PKG_INSTALL_FILE\winlogbeat.yml`" --path.home `"$workdir`" --path.data `"$env:PROGRAMDATA\winlogbeat`" --path.logs `"$env:PROGRAMDATA\winlogbeat\logs`" -E logging.files.redirect_stderr=true" |Out-Null
    
        Try {
            Start-Process -FilePath sc.exe -ArgumentList 'config winlogbeat start=delayed-auto'
        }
        Catch { Write-Host -f red "An error occurred setting the service to delayed start." }
        Write-Host -ForegroundColor blue -BackgroundColor white "=> [OK] Install winlogebeat"
    }

    #######################################################
    Write-Host "4. Setup winlogbeat.yml : " -NoNewline
    $CONF_FILEL_EXISTS = [System.IO.File]::Exists("C:\Program Files\$PKG_INSTALL_FILE\winlogbeat.yml")
    if ($CONF_FILEL_EXISTS) {
        Invoke-WebRequest -Uri $PKG_URL/conf/winlogbeat.yml -OutFile "C:\Program Files\$PKG_INSTALL_FILE\winlogbeat.yml"
        Write-Host -ForegroundColor blue -BackgroundColor white "=> [OK] Setup winlogebeat.yml"
        Remove-Item $DOWNLOAD_PATH\$PKG_FILE.zip
    }

    $RESULT_MSG = @"
========================

Install Complete. Please excute below command.
CMD: Powershell Start-Service winlogbeat
"@

    #######################################################
    if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor green "$($RESULT_MSG)"
    }
} else {
    Write-Host -ForegroundColor red -BackgroundColor white "=> [FAIL] Already installed winlogebeat, please check."
}

$ProgressPreference = $OriginalPref