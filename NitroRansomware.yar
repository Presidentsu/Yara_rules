rule nitroransomware {
    meta:
        author = "PresidentSU"
        Description = "Rule for detecting Nitroransomware"
        filetype = ".NET executable"
    strings:
        $s1 = "DECRYPT_PASSWORD"
        $s2 = "https://canary.discord.com/api/webhooks/832337573137481738/CLEu4D_JA7ZHqWw480anTMj55DiipiCfvTOZKWyxtYoOBT5NqVUqxnWgq_wsjiGO4IoT" ascii
        $s3 = ".givenitro"
        $s4 = "NitroRansomware"
        $s5 = "textBox1.Text"
        $s6 = "Invalid Nitro"
        $s7 = "Nitro Ransomware"
        $s8 = "Key is correct. Decrypting files..."
        $mz = "MZ"
    condition:
        $mz at 0 and any of them

}