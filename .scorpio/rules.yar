rule reverse_shell { strings: $a = "/dev/tcp/" $b = "pty.spawn" $c = "TCPClient(" $d = /nc(at)? .{0,40} -e / condition: any of them }
rule credential_theft { strings: $a = ".ssh/id_rsa" $b = ".aws/credentials" $c = "Login Data" $d = "wallet.dat" $e = ".docker/config.json" condition: any of them }
rule persistence { strings: $a = "crontab -" $b = "/etc/systemd/system/" $c = "LaunchAgents" $d = "CurrentVersion\\Run" nocase $e = "schtasks /create" nocase condition: any of them }
rule privilege { strings: $a = "/etc/sudoers" $b = "NOPASSWD:" condition: any of them }
rule cloud_metadata { strings: $a = "169.254.169.254" $b = "metadata.google.internal" condition: any of them }
rule miner { strings: $a = "stratum+tcp://" $b = "xmrig" nocase condition: any of them }
rule obfuscated_exec { strings: $a = /eval\s*\(\s*(atob|Buffer\.from)\(/ $b = /exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads)/ condition: any of them }
rule download_exec { strings: $a = /(curl|wget) [^\n|]{0,200}\| *(ba)?sh/ condition: $a }
