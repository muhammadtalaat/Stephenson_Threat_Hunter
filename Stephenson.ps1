Remove-Variable * -ErrorAction SilentlyContinue
$PHD = New-Object System.Management.Automation.Host.ChoiceDescription '&Remotely', 'Remotely'
$LSD = New-Object System.Management.Automation.Host.ChoiceDescription '&Local', 'Local'
$options = [System.Management.Automation.Host.ChoiceDescription[]]($LSD,$PHD)


Write-Host "   _____ _             _                                  _    _             _                   __        ___  
  / ____| |           | |                                | |  | |           | |                 /_ |      / _ \ 
 | (___ | |_ ___ _ __ | |__   ___ _ __  ___  ___  _ __   | |__| |_   _ _ __ | |_ ___ _ __  __   _| |     | | | |
  \___ \| __/ _ \ '_ \| '_ \ / _ \ '_ \/ __|/ _ \| '_ \  |  __  | | | | '_ \| __/ _ \ '__| \ \ / / |     | | | |
  ____) | ||  __/ |_) | | | |  __/ | | \__ \ (_) | | | | | |  | | |_| | | | | ||  __/ |     \ V /| |  _  | |_| |
 |_____/ \__\___| .__/|_| |_|\___|_| |_|___/\___/|_| |_| |_|  |_|\__,_|_| |_|\__\___|_|      \_/ |_| (_)  \___/ 
                | |                                                                                             
                |_|                                                                                             

 #########################Prerequisites######################################
                          For Remote Scan

#1- Allow inbound port TCP-135 (in Windows firewall, endpoint firewall, and network firewalls)
#2- Outbound random ports ranging from 1022-5000 and 49152-65535 must also be permitted
#3- Inbound port TCP-445 for SMB (RPC dependency) must be open.  
#4- Use High-Privilege User
                                                                                                               
 #########################Prerequisites######################################                                                                                                                  
                                                                                                                       " -ForegroundColor green
$title = 'Stephenson'
$message = "Chose From Options Local or Remotely"
$result = $host.ui.PromptForChoice($title, $message, $options, 0)
if ($result -eq 0) {

$RegistryScanL = New-Object System.Management.Automation.Host.ChoiceDescription '&Registry Scan', 'Registry Scan'
$EventL = New-Object System.Management.Automation.Host.ChoiceDescription '&EventViewer Scan', 'EventViewer Scan'
$pathScanL = New-Object System.Management.Automation.Host.ChoiceDescription '&File Scan', 'File Scan'
$hashL = New-Object System.Management.Automation.Host.ChoiceDescription '&Hash Scan', 'Hash Scan'
$optionsL = [System.Management.Automation.Host.ChoiceDescription[]]($RegistryScanL,$EventL,$pathScanL,$hashL)
$title = 'Stephenson'
$message2 = "Choose From Options Registry Scan or EventViewer Scan or Path Scan or Hash" 
$result2 = $host.ui.PromptForChoice($title, $message2, $optionsL, 0)
$Server = hostname

if ($result2 -eq 0) {

################Registry###########################################
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Server)
$RegType = [Microsoft.Win32.RegistryHive]::LocalMachine

$path1 = Read-Host -Prompt 'What is the registry path? (e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Run\)' 
$RegKeyCU1  = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegType, $Server)
$strRegKeyCU1  = $RegKeyCU1.OpenSubKey($path1)
$subkeys1 = $strRegKeyCU1.GetValueNames()
$keyscan = Read-Host -Prompt 'What is the key value? (e.g. wscript.exe //B "*\*.vbs") Note: Wildcard is accepted'
$output = @()
Write-Host "LocalMachine Registry"
Foreach ($subkey1 in $subkeys1) {
    $key1 = $strRegKeyCU1.GetValue("$subkey1")
    If ($key1 -like $keyscan) {
        Write-Host "The Run Registry exists in $subkey1 = $key1"
        $output += [PSCustomObject]@{
            Key = $subkey1
            Value = $key1
            Location = $path1
        }
    }
if($output){
$output | Export-Csv -Path "c:\Local_Reg_Scan_Output.csv" -NoTypeInformation
}
}


}
elseif ($result2 -eq 1) {
$event1 = Read-Host -Prompt 'What is the Log Name? (e.g. Microsoft-Windows-Sysmon/Operational)'
$ID1 = Read-Host -Prompt 'What is the ID Number? (e.g. 22)'
$messagescan = Read-Host -Prompt 'What is the content needed to be scanned? (e.g. *google*) Note: Wildcard is accepted'
try {
    $events = Get-WinEvent -ComputerName $Server -FilterHashTable @{logname = $event1; ID = $ID1} | Where-Object { $_.Message -like $messagescan } -ErrorAction SilentlyContinue
    $output = @()
    foreach ($event in $events) {
        $eventData = [PSCustomObject]@{
            Server = $Server
            LogName = $event.LogName
            ID = $event.Id
            TimeCreated = $event.TimeCreated
            Message = $event.Message
        }
        $output += $eventData
    }
    if($output){
    $output | Export-Csv -Path "c:\Local_EventLog_Scan_Output.csv" -NoTypeInformation
    }

} catch {
}

}
elseif ($result2 -eq 2) {
$allfiles = New-Object System.Management.Automation.Host.ChoiceDescription '&All Partition Scan', 'All Partition Scan'
$selected = New-Object System.Management.Automation.Host.ChoiceDescription '&Selected Partition Scan', 'Selected Partition Scan'
$optionsf = [System.Management.Automation.Host.ChoiceDescription[]]($allfiles,$selected)
$title = 'Stephenson'
$messagef = "Choose From Options All Partition Scan or Selected Partition Sca " 
$resultf = $host.ui.PromptForChoice($title, $messagef, $optionsf, 0)
if ($resultf -eq 0) {
$testpath1 = Read-Host -Prompt 'What is the filename to search for? (e.g., Test.exe)'
$output = @()
$disks = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
foreach ($disk in $disks) {
    $rootPath = $disk.DeviceID + '\'
    $files = Get-ChildItem -Path $rootPath -File -Recurse -Filter $testpath1

    foreach ($file in $files) {
        $filePath = $file.FullName
        Write-Host "Checking $filePath"

        $output += [PSCustomObject]@{
            Drive = $disk.DeviceID
            Path = $rootPath
            FileName = $testpath1
            FilePath = $filePath
            Size = $file.Length
            LastModified = $file.LastWriteTime
            LastAccessed = $file.LastAccessTime
            Created = $file.CreationTime
        }
    }
}
}
elseif ($resultf -eq 1) {
$testpath1 = Read-Host -Prompt 'What is the root folder path to start the scan? (e.g., c$\Windows)'
$testfile1 = Read-Host -Prompt 'What is the filename to search for? (e.g., Test.exe)'
$output = @()
$files = Get-ChildItem -Path "\\$Server\$testpath1" -File -Recurse -Filter $testfile1
foreach ($file in $files) {
    $filePath = $file.FullName
    Write-Host "Checking $filePath"
    
    if (Test-Path -Path $filePath) {
        Write-Host "File exists on $Server."
        $output += [PSCustomObject]@{
            Server = $Server
            Path = $testpath1
            FileName = $testpath1
            FilePath = $filePath
            Size = $file.Length
            LastModified = $file.LastWriteTime
            LastAccessed = $file.LastAccessTime
            Created = $file.CreationTime
            FileExists = $true
        }
    } else {
        Write-Host "File does NOT exist on $Server."
        $output += [PSCustomObject]@{
            Server = $Server
            Path = $testpath1
            FileName = $testpath1
            FilePath = $filePath
            Size = $file.Length
            LastModified = $file.LastWriteTime
            LastAccessed = $file.LastAccessTime
            Created = $file.CreationTime
            FileExists = $false
        }
        }
    }
}

if($output){
$output | Export-Csv -Path "c:\Local_File_Scan_Output.csv" -NoTypeInformation
}
}
elseif ($result2 -eq 3) {
$parentFolderPath = Read-Host -Prompt 'What is the root folder path to start the scan? (e.g., c:\Temp)'
$hashAlgorithm = Read-Host "Choose a hash algorithm (MD5, SHA1, SHA256)"
$hashFilePath = Read-Host -Prompt 'What is the textfile path which contain hashes to start the scan? (e.g., C:\Path\To\Hashes.txt)'
$hashes = Get-Content $hashFilePath
if ($hashAlgorithm -notin ("MD5", "SHA1", "SHA256")) {
    Write-Host "Invalid hash algorithm choice. Please choose MD5, SHA1, or SHA256."
    exit
}
$matchingFiles = @()
$files = Get-ChildItem $parentFolderPath -File -Recurse
foreach ($file in $files) {
    $hash = Get-FileHash $file.FullName -Algorithm $hashAlgorithm
    if ($hashes -contains $hash.Hash) {
        $matchingFiles += [PSCustomObject]@{
            FilePath = $file.FullName
            Hash = $hash.Hash
        }
    }
}
if($matchingFiles){
$matchingFiles | Export-Csv -Path "C:\Local_MatchingFiles_$hashAlgorithm.csv" -NoTypeInformation
Write-Host "Matching files have been exported to MatchingFiles.csv"
}

}
}
elseif ($result -eq 1) {

$RegistryScanR = New-Object System.Management.Automation.Host.ChoiceDescription '&Registry Scan', 'Registry Scan'
$EventR = New-Object System.Management.Automation.Host.ChoiceDescription '&EventViewer Scan', 'EventViewer Scan'
$pathScanR = New-Object System.Management.Automation.Host.ChoiceDescription '&Path Scan', 'Path Scan'
$HashScanR = New-Object System.Management.Automation.Host.ChoiceDescription '&Hash Scan', 'Hash Scan'
$optionsR = [System.Management.Automation.Host.ChoiceDescription[]]($RegistryScanR,$EventR,$pathScanR,$HashScanR)
$title = 'Stephenson'
$message3 = "Chose From Options Registry Scan or EventViewer Scan or Path Scan"
$result3 = $host.ui.PromptForChoice($title, $message3, $optionsR, 0)

if ($result3 -eq 0) {
$subnet = Read-Host -Prompt 'What is your Network IP? (e.g. 192.168.1)'
$ipRange = Read-Host 'What is your IP Address range? (e.g. 2:5)'

if ($ipRange -match '^\d+:\d+$') {
    $startIP, $endIP = $ipRange -split ':'
    $ipsRange = [int]$startIP..[int]$endIP
} else {
    Write-Host 'Input not in correct format.'
}

# Prompt for the registry key and path
$registryPath = Read-Host -Prompt 'What is the registry path? (e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Run\)'
$keyscan = Read-Host -Prompt 'What is the key value? (e.g. wscript.exe //B "*\*.vbs") Note: Wildcard is accepted'

# Create an array to store the output
$output = @()

foreach ($ip in $ipsRange) {
    $server = "$subnet.$ip"

    # Test Connection
    $status = Test-Connection $server -Count 1 -Quiet

    if (!$status) {

 Write-Host "Server $server is not available."
        }
     else {
        Write-Host "Scanning Machine: $server"

        # Start Service
        cmd.exe /c "sc \\$server config remoteregistry start= auto"
        cmd.exe /c "sc \\$server start remoteregistry"

        # Registry
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $server)
        $RegType = [Microsoft.Win32.RegistryHive]::LocalMachine
        $path1 = $registryPath

        $RegKeyCU1 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegType, $server)
        $strRegKeyCU1 = $RegKeyCU1.OpenSubKey($path1)
        $subkeys1 = $strRegKeyCU1.GetValueNames()

        Write-Host "RemoteMachine Registry"

        foreach ($subkey1 in $subkeys1) {
            $key1 = $strRegKeyCU1.GetValue("$subkey1")

            # Check Registry For Local Machine
            if ($key1 -like $keyscan) {
                Write-Host "The  Registry exists KeyName $subkey1 in KeyValue  $key1 on $server"
                $outputData = [PSCustomObject]@{
                    Server = $server
                    RegistryPath = $path1
                    Key = $subkey1
                    KeyValue = $key1
                }
            } else {

            Write-Host "No matching REG found in path $registryPath on $server."

                }
            }
            $output += $outputData
        }
        # Export the output to a CSV file
        if($output){
$output | Export-Csv -Path "c:\Remote_Reg_Scan.csv" -NoTypeInformation
}
    }
    }
elseif ($result3 -eq 1) {
$subnet = Read-Host -Prompt 'What is your Network IP? (e.g. 192.168.1)'
$ipRange = Read-Host 'What is your IP Address range? (e.g. 2:5)'

if ($ipRange -match '^\d+:\d+$') {
    $startIP, $endIP = $ipRange -split ':'
    $ipsRange = [int]$startIP..[int]$endIP
} else {
    Write-Host 'Input not in the correct format.'
}
$event1 = Read-Host -Prompt 'What is the Log Name? (e.g. Microsoft-Windows-Sysmon/Operational)'
$ID1 = Read-Host -Prompt 'What is the ID Number? (e.g. 22)'
$messagescan = Read-Host -Prompt 'What is the content needed to be scanned? (e.g. *google*) Note: Wildcard is accepted'

foreach ($ip in $ipsRange) {
    $server = "$subnet.$ip"
    $status = Test-Connection $server -Count 1 -Quiet

    if (!$status) {
        Write-Host "Server $server is not available."
    } else {
        Write-Host "Scanning Machine: $server"

        $output = @()
        
        try {
            $events = Get-WinEvent -ComputerName $server -FilterHashTable @{logname="$event1"; ID="$ID1"} | Where-Object {$_.Message -like "$messagescan"} -ErrorAction SilentlyContinue

            if ($events.Count -gt 0) {
                Write-Host "Event(s) found on $server."
                foreach ($event in $events) {
                    $outputData = [PSCustomObject]@{
                        Server = $server
                        LogName = $event1
                        EventID = $ID1
                        Message = $event.Message
                        TimeCreated = $event.TimeCreated
                    }
                    $output += $outputData
                }
                if($output){
                $output | Export-Csv -Path "c:\Remote_EventViewerScan_$server.csv" -NoTypeInformation
                }
            } else {
                Write-Host "No matching events found on $server."
            }
        } catch {
            Write-Host "Error occurred while retrieving events from $server."
        }
    }
}
}
elseif ($result3 -eq 2) {
$subnet = Read-Host -Prompt 'What is your Network IP? (e.g. 192.168.1)'
$ipRange = Read-Host 'What is your IP Address range? (e.g. 2:5)'

if ($ipRange -match '^\d+:\d+$') {
    $startIP, $endIP = $ipRange -split ':'
    $ipsRange = [int]$startIP..[int]$endIP
} else {
    Write-Host 'Input not in the correct format.'
}

$folderPath = Read-Host -Prompt 'What is the parent folder path to search? (e.g. C$\Path\To\Folder)'
$filename = Read-Host -Prompt 'What is the filename to search for? (e.g. example.txt)'

foreach ($ip in $ipsRange) {
    $server = "$subnet.$ip"
    $status = Test-Connection $server -Count 1 -Quiet

    if (!$status) {
        Write-Host "Server $server is not available."
    } else {
        Write-Host "Scanning Machine: $server"

        $output = @()
        $folderExists = Test-Path "\\$server\$folderPath"

        if ($folderExists) {
            $foundFiles = Get-ChildItem -Path "\\$server\$folderPath" -Filter $filename -File -Recurse

            if ($foundFiles.Count -gt 0) {
                foreach ($file in $foundFiles) {
                    $outputData = [PSCustomObject]@{
                        Server = $server
                        FolderPath = $folderPath
                        FileName = $filename
                        FilePath = $file.FullName
                    }
                    $output += $outputData
                }
                if($output){
                $output | Export-Csv -Path "c:\Remote_FileScan_$server.csv" -NoTypeInformation
                }
            } else {
                Write-Host "No matching files found in folder $folderPath on $server."
            }
        } else {
            Write-Host "Folder $folderPath does not exist on $server."
        }
    }
}
}
elseif ($result3 -eq 3) {
$subnet = Read-Host -Prompt 'What is your Network IP? (e.g. 192.168.1)'
$ipRange = Read-Host 'What is your IP Address range? (e.g. 2:5)'

if ($ipRange -match '^\d+:\d+$') {
    $startIP, $endIP = $ipRange -split ':'
    $ipsRange = [int]$startIP..[int]$endIP
} else {
    Write-Host 'Input not in the correct format.'
    exit
}

$folderPath = Read-Host -Prompt 'What is the root folder path to start the scan? (e.g., C$\Temp)'
$hashAlgorithm = Read-Host "Choose a hash algorithm (MD5, SHA1, SHA256)"
$hashFilePath = Read-Host -Prompt 'What is the text file path which contains hashes to start the scan? (e.g., C:\Path\To\Hashes.txt)'
$hashes = Get-Content $hashFilePath
if ($hashAlgorithm -notin ("MD5", "SHA1", "SHA256")) {
    Write-Host "Invalid hash algorithm choice. Please choose MD5, SHA1, or SHA256."
    exit
}
$matchingFiles = @()
foreach ($ip in $ipsRange) {
    $server = "$subnet.$ip"
    $status = Test-Connection $server -Count 1 -Quiet

    if (!$status) {
        Write-Host "Server $server is not available."
    } else {
        Write-Host "Scanning Machine: $server"
        $folderContents = Get-ChildItem "\\$server\$folderPath" -File -Recurse

        foreach ($file in $folderContents) {
            $hash = Get-FileHash $file.FullName -Algorithm $hashAlgorithm
            if ($hashes -contains $hash.Hash) {
                $matchingFiles += [PSCustomObject]@{
                    Server = $server
                    FilePath = $file.FullName
                    Hash = $hash.Hash
                }
            }
        }
    }
}
if($matchingFiles){
$matchingFiles | Export-Csv -Path "C:\Remote_MatchingFiles_$hashAlgorithm.csv" -NoTypeInformation

Write-Host "Matching files have been exported to MatchingFiles.csv"
}
}
}





