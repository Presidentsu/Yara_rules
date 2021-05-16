import "pe"

rule BabukRansomware{
    meta:
        author = "PresidentSU"
        description = "Babuk Ransomware"
        file_type = "Ransomware executable"
        
    strings:
            $importDll1 = "netapi32.dll" nocase
            $importDll2 = "rstrtmgr.dll" nocase
            $importDll3 = "user32.dll" nocase
            $importDll4 = "kernel32.dll" nocase
            $importDll5 = "advapi32.dll" nocase
            $importDll6 = "shell32.dll" nocase
            $importDll7 = "mpr.dll" nocase
        
            $link1 = "http://tsu2dpiiv4zjzfyq73eibemit2qyrimbbb6lhpm6n5ihgallom5lhdyd.onion/"
            $link2 = "https://www.torproject.org/download/"
            $link3 = "http://wavbeudogz6byhnardd2lkp2jafims3j7tj6k6qnywchn2csngvtffqd.onion/" 
        
            $cmd = "delete shadows /all /quiet" fullword wide
        
            $s1 = "babuk ransomware greetings you" fullword wide
            $s2 = "How To Restore Your Files.txt" fullword ascii
            $s3 = "Wow64DisableWow64FsRedirection"
            $s4 = "GetVolumePathNamesForVolumeName"
            $s5 = "SetVolumeMountPoint"
            $s6 = "ControlService"
            $s7 = "NetApiBufferFree"
            $s8 = "NetShareEnum"
            $s9 = "RmStartSession"
            $s10 = "RmGetList"
            $s11 = "WNetOpenEnum"
            $s12 = "WNetGetConnection"
            $s13 = "CreateToolHelp32Snapshot"
            $s14 = "GetCurrentProcessId"
            $s15 = "ShellExecute"
            $s16 = "SetProcessShutdownParameters"
            $s17 = "CryptAcquireContext"
            $s18 = "CryptReleaseContext"
            $s19 = "CryptGenRandom"
            $s20 = "BackupExecAgentBrowser" 
            $s21 = "BackupExecVSSProvider" 
            $s22 = "BackupExecAgentAccelerator" 
            $s23 = "BackupExecJobEngine" 
            $s24 = "WaitForMultipleObjects" 
            $ransomText1 = "Data leakage"
            $ransomText2 = "Contact"
    condition:
            uint16(0)==0x5A4D  and (all of ($importDll*)) and (2 of ($link*)) and (12 of ($s*)) and (any of ($ransomText*))  and $cmd
}