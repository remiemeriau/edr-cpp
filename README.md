# edr-cpp

Small antivirus / EDR written in C++. We built it together as a side project to play a bit with fanotify, libpcap and a homemade YARA-like engine.

The idea is to scan files on the fly as they get written, watch network traffic for suspicious HTTP/SMTP/Telnet activity, and compare SHA-256 hashes against a list of known IOCs. Nothing groundbreaking, but it runs and stays pretty light (~3 MB resident at idle).

## Build

You'll need g++ (C++23) and libpcap-dev. Then:

```sh
make
```

## Running it

```sh
sudo ./antivirus <directory_to_watch> <rule_file>
```

sudo is required because of fanotify and libpcap. Example:

```sh
sudo ./antivirus /tmp rule.yar
```

On startup it loads `ioc_hashes.txt`, parses the rules, spawns a DPI thread on `lo`, and starts listening for `FAN_CLOSE_WRITE` events on the directory. Every modified file gets matched against all rules, and its hash is checked too.

## Writing rules

Simplified YARA syntax. Looks like this:

```
rule MyRule {
    strings:
        $a = "some text"
        $b = { DE AD BE EF }
        $c = /regex.*/
    condition:
        $a or $b
}
```

Three pattern types are supported: quoted strings, hex between braces, regex between slashes. The condition syntax is intentionally minimal — either a single variable, or two variables joined by `and` or `or`. No parentheses, no nested combinations. It's a known limitation of the parser.

The provided `rule.yar` ships with a handful of examples (reverse shells, miners, ransom notes, webshells, etc.) to play with.

## Layout

```
src/main.cpp   entry point, fanotify loop, .yar parser
src/yara.cpp   scanFile() and the matchers
src/dpi.cpp    libpcap capture, TCP/UDP parsing, scanBuffer()
src/ioc.cpp    hash loading + popen(sha256sum)
rule.yar       sample rules
ioc_hashes.txt list of known SHA-256 hashes
```

## What it doesn't do

- No behavioral detection — it's pure signature matching.
- Encrypted traffic (TLS/HTTPS) is invisible, only plaintext protocols are visible.
- A single directory at a time, and no recursion (fanotify is set up with MOUNT but we filter by path prefix).
- Alerts are logged but nothing is quarantined or blocked.
