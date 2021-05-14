rule snake_keylogger{
    meta:
            author = "PresidentSU"
            description = "Snake Keylogger"
            file = ".NET executable"
    strings:
            $id1 = "SNAKE-KEYLOGGER"
            $id2 = "COVID19"
            $id3 = "COVIDRandomz"
            $id4 = "FFDecryptor.SNAKE-KEYLOGGER"
            $id5 = "COVIDisDanger"
            $id6 = "758F8B70-D9D0-488D-ABF9-F5066E5D1A0E" wide
            $s1 = "Clipboard Logs ID - STOR Pc Name:  | Snake Keylogger" ascii
            $s2 = "Screenshot Logs ID - Screenshot |  | Snake Keylogger" ascii
            $s3 = "KeystrokesKeylogger |  | Snake Keylogger" ascii
            $hex_string = "{2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 53 2D 2D 2D 2D 2D 2D 2D 2D 4E 2D 2D 2D 2D 2D 2D 2D 2D 41 2D 2D 2D 2D 2D 2D 2D 2D 4B 2D 2D 2D 2D 2D 2D 2D 2D 45 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D}"
    condition:
            any of them
}