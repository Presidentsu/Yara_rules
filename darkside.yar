import "pe"


rule DarksideRansomware{
    meta:
        author = "PresidentSU"
        description = "Darkside ransomware executable"
        file_type = "executable"
    strings:
        $importdll1 = "KERNEL32.dll"
        $importdll2 = "WTSAPI32.dll"
        $importdll3 = "USER32.dll"
        $s1 = {68 BB F3 C9 00 E8 3E AB AC FF 48 F7 D0 F5 85 D1 A8 63 8D 80 A7 35 E3 6A 80 F9 16 F9 0F C8 F5 33 D8 }        
        $s2 = "GetUserObjectInformationW"
        $s3 = "VirtualQuery"
        $s4 = "GetProcessWindowStation"
        $h1 = {FF 55 C3 33 D8 66 3B D1 84 C3 03 F0 E9 60 36 B5 FF F7 F1}
        $h2  = {2B A7 7A 41 BC 1D B2 2D BF 49 C3 F5 CA 48 12 D8 2F 40 B3 99 24 7A F7 FB 55 CD 99 BF 48 24 41}
    condition:
        uint16(0) == 0x5A4D and (all of ($importdll*)) and (all of ($s*)) and (any of ($h*))
}