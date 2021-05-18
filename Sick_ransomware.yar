import "pe"

rule Sick_Ransomware_payload {
    meta:
        author = "PresidentSU"
        description = "Sick Ransomware executable"
        Side_note = "This son of a bitch ransomware sucks tho"
        File_type = "PE file with sick ransomware payload"
    strings:
        $importDll = "mscoree.dll" nocase
        $s1 = "System.Security.Cryptography" nocase
        $s2 = "System.Text.RegularExpression" nocase
        $s3 = "ICryptoTransform" nocase
        $hex1 = {75 00 73 00 65 00 72 00 70 00 72 00 6F 00 66 00 69 00 6C 00 65}
        $hex2 = {68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F 00 67 00 68 00 6F 00 73 00 74 00 62 00 69 00 6E 00 2E 00 63 00 6F 00 6D 00 2F 00 70 00 61 00 73 00 74 00 65 00 2F 00 79 00 75 00 4C 00 62 00 5A}
        $hex3 = {54 00 65 00 78 00 74 00 66 00 69 00 6C 00 65}
        $hex4 = {20 00 48 00 45 00 4C 00 50 00 2E 00 74 00 78 00 74}
        $hex5 = {79 00 6F 00 75 00 72 00 20 00 44 00 65 00 73 00 6B 00 74 00 6F 00 70 00 21 00 00 15 41 00 74 00 74 00 65 00 6E 00 74 00 69 00 6F 00 6E 00 21}
        $hex6 = {5F 00 6B 00 39 00 35 00 2C 00 51 00 38 00 7A 00 40 00 4C 00 70 00 30 00 51 00 2E 00 45 00 71 00 2F 00 59 00 4F 00 55 00 6D 00 34 00 69 00 62 00 74 00 2E 00 61 00 25 00 3D 00 4A}
        $extension = {2E 00 73 00 69 00 63 00 6B}
    condition:
        uint16(0) == 0x5A4D and $importDll and (all of ($s*)) and (4 of ($hex*)) and $extension
}