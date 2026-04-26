rule SimpleMalware {
    strings:
        $shell = "bin/bash"
        $shadow = "/etc/shadow"
        $hex_test = { 4D 41 4C 57 41 52 45 }
    condition:
        $shell or $shadow
}