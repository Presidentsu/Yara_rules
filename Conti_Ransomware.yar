import "pe"
rule Conti_ransomware_payload{
    meta:
        author = "PresidentSU"
        description = "Conti Ransomware package"
        file_type = "Conti Ransomware executable"
    strings: 
        $importDll1 = "KERNEL32.dll" nocase
        $importDll2 = "SHLWAPI.dll" nocase
        $importDll3 = "USER32.dll" nocase
        
        $s1 = "PathIsDirectory"
        $s2 = "FindFirstFileEx"
        $s3 = "FindNextFile"
        $s4 = "GetCurrentProcessId"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetEnvironmentStrings"
        $s7 = "RaiseException"
        $s8 = "GetModuleFileName"
        $s9 = "GetModuleHandleEx"
        $s10 = "IsDebuggerPresent"
        $s11 = "LCMapStringEx"
        $s12 = "UnhandledExceptionFilter"
        $s13 = "SetUnhandledExceptionFilter"

        $Hex1 = {3F 41 56 74 79 70 65 5F 69 6E 66 6F 40 40}
        $Hex2 = {3F 41 56 62 61 64 5F 61 72 72 61 79 5F 6E 65 77 5F 6C 65 6E 67 74 68 40 73 74 64 40 40}
        $Hex3 = {3F 41 56 6C 65 6E 67 74 68 5F 65 72 72 6F 72 40 73 74 64 40 40}
        $Hex4 = {3F 41 56 62 61 64 5F 61 6C 6C 6F 63 40 73 74 64 40 40}
        $Hex5 = {3F 41 56 65 78 63 65 70 74 69 6F 6E 40 73 74 64 40 40}
    condition:
        uint16(0) == 0x5A4D and (all of ($importDll*)) and (8 of ($s*)) and (3 of ($Hex*))
}