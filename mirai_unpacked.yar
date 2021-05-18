import "elf"

rule mirai_botnet_unpacked {
    meta:
        author = "PresidentSU"
        description = "Mirai botnet malware unpacked version"
        file_type = "ELF"
    strings:
        $s1 = "attack_method_udpgeneric" nocase
        $s2 = "attack_method_udpplain" nocase
        $s3 = "attack_get_opt_ip" nocase
        $s4 = "attack_kill_all" nocase
        $s5 = "attack_ongoing" nocase
        $s6 = "attack_init" nocase
        $s7 = "attack_method_tcpsyn" nocase
        $s8 = "attack_trim" nocase
        $s9 = "attack_method_tcpxmas" nocase
        $s10 = "attack_parse" nocase
        $s11 = "attack_get_opt_int" nocase
        $s12 = "attack_method_std" nocase
        $s13 = "attack_get_opt_str" nocase
        $s14 = "attack_method_tcpack" nocase
        $s15 = "attack_method_greeth" nocase
        $s16 = "attack_method_greip" nocase
        $s17 = "attack_method_udpvse" nocase
        $s18 = "attack_start" nocase
        $s19 = "attack_method_tcpstomp" nocase
        $s20 = "attack_method_udpdns" nocase
        $killer1 = "killer_kill_by_port" nocase
        $killer2 = "killer_realpath" nocase
        $killer3 = "killer_realpath_len" nocase
        $killer4 = "killer_init" nocase
        $killer5 = "killer_kill" nocase
        $killer6 = "killer_pid" nocase
        $directory1 = "/home/landley/aboriginal/" nocase
        $directory2 = "/proc/stat" nocase
        $directory3 = "/proc/cpuinfo" nocase
        $directory4 = "/sys/devices/system/cpu" nocase
        $directory5 = "/dev/null" nocase
    condition:
        uint32(0) == 0x464C457F and (13 of ($s*)) and (4 of ($killer*)) and (all of ($directory*))


        
}