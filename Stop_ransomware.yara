import "pe"

rule Stop_Ransomware_Unpacked_PE
{
    meta:
        author = "PresidentSU"
        File_type = "PE executable"
        description = "Stop ransomware"
        file_hash_S256 = "2a8f13cc0d990ecfd9c2a6f3120b97bc9faa27251e54c1d2e27f80453f29f60a"
    strings:
        $imports1 = "kernel32.dll" nocase
        $imports2 = "user32.dll" nocase
        $malfuncs1 = "HeapQueryInformation"
        $malfuncs2 = "VirtualProtect" nocase ascii
        $malfuncs3 = "IsSystemAutomatic" nocase ascii
        $malfuncs4 = "GetSystemWow64Directory" nocase ascii
        $malfuncs5 = "FindFirstFileEx" nocase ascii
        $malfuncs6 = "GetPrivateProfileSectionNames" nocase ascii
        $malfuncs7 = "WriteProfileSection" nocase ascii
        $s1 = {44 00 75 00 78 00 69 00 72 00 69 00 6E 00 69 00 6A 00 6F 00 6A 00 61 00 62 00 20 00 6D 00 6F 00 6C 00 69 00 73 00 65 00 64 00 65 00 20 00 64 00 65 00 6B}
        $s2 = {44 00 75 00 78 00 69 00 72 00 69 00 6E 00 69 00 6A 00 6F 00 6A 00 61 00 62 00 20 00 6D 00 6F 00 6C 00 69 00 73 00 65 00 64 00 65 00 20 00 64 00 65 00 6B}
        $s3 = {73 00 61 00 66 00 61 00 6D 00 6F 00 20 00 6D 00 65 00 77 00 69 00 20 00 79 00 61 00 68 00 61 00 66 00 69 00 64}
        $s4 = {6E 00 65 00 79 00 65 00 76 00 6F 00 20 00 79 00 65 00 73 00 6F 00 72 00 61 00 66 00 75 00 6A 00 75}
        $s5 = "Wabihozetagedoz. Zosafovanetumo noxuteci hopakace nojepod herubodahutuwed."
        $s6 = "Viyiku cavuyomafego zuja lizoku kisaholexoh"
    condition:
        uint16(0) == 0x5A4D and (all of ($imports*)) and (5 of ($malfuncs*)) and (4 of ($s*))
}