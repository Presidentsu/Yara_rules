import "pe"

rule Torjan_FromBook{
    meta:
        author = "PresidentSU"
        description = "Trojan FormBook"
        file_type = ".NET Executable"
    strings:
        $importDll1 = "mscoree.dll" nocase
        $importDll2 = "user32.dll" nocase
        $importDll3 = "shell32.dll" nocase
        $s1 = "SHGetFileInfo"
        $s2 = "System.Security.AccessControl"
        $s3 = "ObfuzFuncs" nocase 
        $s4 = "BatSettingObz" nocase
        $s5 = "GeneratePorsentage"
        $s6 = "ITypeLibImporterNotifySink" nocase
        $s7 = "BatMethod1"
        $s8 = "BatMethod2"
        $s9 = "BatMethod3"
        $s10 = "BatOfUser" nocase
        $RegKey1 = {53 00 4F 00 46 00 54 00 57 00 41 00 52 00 45 00 5C 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F 00 66 00 74 00 5C 00 49 00 6E 00 74 00 65 00 72 00 6E 00 65 00 74 00 20 00 45 00 78 00 70 00 6C 00 6F 00 72 00 65 00 72}
        $RegKey2 = "RegistryKey" nocase
    condition:
        uint16(0) == 0x5A4D and (all of ($importDll*)) and (6 of ($s*)) and (all of ($RegKey*))

}