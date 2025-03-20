 Write-Host @"
========================
Install winlogbeat for ELK.
========================"

#######################################################
Write-Host "1. Add host."
$HOST_FILE = 'C:\Windows\System32\drivers\etc\hosts'
$HOST_FILE_CONTENTS = @"

################################
### ELK
192.168.1.1    elk
"@

if (Get-Content $HOST_FILE |Select-String "elk" -Quiet) {
    Write-Host "Already Setting"
} else {
 
    Add-Content -Path $HOST_FILE -Value $HOST_FILE_CONTENTS
}

#######################################################
Write-Host "2. Download winlogbeat."
$PKG_URL = 'http://192.168.1.1/winlogbeat/windows2019'
$PKG_FILE = 'winlogbeat-8.12.1-windows-x86_64'
$PKG_INSTALL_FILE = 'winlogbeat-8.12.1'
$DOWNLOAD_PATH = 'C:\Users\administrator\Downloads'

$PKG_FILE_EXISTS = [System.IO.File]::Exists("$DOWNLOAD_PATH\$PKG_FILE")
$PKG_INSTALL_EXISTS = [System.IO.File]::Exists("C:\Users\administrator\Downloads\winlogbeat-8.12.1")
if (-Not ($PKG_INSTALL_EXISTS)) {
    if (-Not ($FILE_EXISTS)) {
        Write-Host "-> Download pkg and setup."
        wget -Uri $PKG_URL/$PKG_FILE.zip -OutFile $DOWNLOAD_PATH\$PKG_FILE.zip
    }
    cd $DOWNLOAD_PATH
    Expand-Archive .\$PKG_FILE.zip -DestinationPath .\
    Rename-Item .\$PKG_FILE $PKG_INSTALL_FILE
    mv .\$PKG_INSTALL_FILE "C:\Program Files\"

    if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
        Write-Host "Already created winlogbet.\n so, re-create winlogbeat"
        sc.exe delete winlogbeat 

        New-Service -name winlogbeat `
        -displayName Winlogbeat `
        -binaryPathName "`"C:\Program Files\$PKG_INSTALL_FILE\winlogbeat.exe`" --environment=windows_service -c `"C:\Program Files\$PKG_INSTALL_FILE\winlogbeat.yml`" --path.home `"$workdir`" --path.data `"$env:PROGRAMDATA\winlogbeat`" --path.logs `"$env:PROGRAMDATA\winlogbeat\logs`" -E logging.files.redirect_stderr=true"
    
        Try {
            Start-Process -FilePath sc.exe -ArgumentList 'config winlogbeat start= delayed-auto'
        }
        Catch { Write-Host -f red "An error occurred setting the service to delayed start." }
    }
}

#######################################################
Write-Host "3. Setup winlogbeat."
$CONF_FILEL_EXISTS = [System.IO.File]::Exists("C:\Program Files\$PKG_INSTALL_FILE/winlogbeat.yml")
if (-Not ($CONF_FILEL_EXISTS)) {
    Write-Host "-> Download conf"
    wget -Uri $PKG_URL/conf/winlogbeat.yml -OutFile C:\Program Files\$PKG_INSTALL_FILE/.
}
$RESULT_MSG = @"
#######################################################

Install Complete. Please excute below command.
[ Start-Service winlogbeat ] 

"@

#######################################################
if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
  Write-Host $RESULT_MSG
}


#.\winlogbeat.exe -c C:\Users\administrator\Downloads\winlogbeat.yml
#.winlogbeat.exe -c winlogbeat.yml
# netstat -ano |findstr 192.168.1.1
#
#Get-WinEvent -ListLog * | Format-List -Property LogName
#Get-Eventlog * 
