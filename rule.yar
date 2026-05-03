rule SimpleMalware {
    strings:
        $shell = "bin/bash"
        $shadow = "/etc/shadow"
        $hex_test = { 4D 41 4C 57 41 52 45 }
    condition:
        $shell or $shadow
}

rule nc_reverse_shell {
    strings:
        $nc = "nc -e /bin/sh"
        $bash_tcp = "/dev/tcp/"
    condition:
        $nc or $bash_tcp
}

rule wget_dropper {
    strings:
        $wget = "wget http"
        $curl = "curl -O"
    condition:
        $wget or $curl
}

rule xmrig_miner {
    strings:
        $pool = "stratum+tcp://"
        $xmrig = "xmrig"
    condition:
        $pool or $xmrig
}

rule ransom_note_btc {
    strings:
        $ransom = "your files have been encrypted"
        $btc = "bitcoin"
    condition:
        $ransom and $btc
}

rule eicar_test {
    strings:
        $magic = { 4D 41 4C 57 41 52 45 }
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $magic or $eicar
}

rule sqli_union_select {
    strings:
        $union = /UNION[ ]+SELECT/
        $orone = /OR[ ]+1=1/
    condition:
        $union or $orone
}

rule php_webshell {
    strings:
        $php_eval = "eval($_POST"
        $php_system = "system($_GET"
    condition:
        $php_eval or $php_system
}

rule setuid_persistence {
    strings:
        $sudoers = "/etc/sudoers"
        $setuid = "chmod u+s"
    condition:
        $sudoers or $setuid
}

rule x11_keylogger {
    strings:
        $xinput = "XGrabKeyboard"
        $log = "keylog"
    condition:
        $xinput or $log
}

rule http_pastebin_exfil {
    strings:
        $post = "POST /upload"
        $host = "Host: pastebin"
    condition:
        $post and $host
}
