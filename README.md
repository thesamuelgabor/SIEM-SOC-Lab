# SIEM SOC Lab

## Objective

Build a small SOC lab on Hyper-V: an Active Directory domain with a domain-joined Windows 11 workstation, sending Windows Security, System and Sysmon logs to Splunk Enterprise. The lab is the base for writing SPL detections, hardening AD and simulating attacks such as Kerberoasting.

### Skills Learned

- Building an isolated multi-VM lab in Hyper-V (internal switch, Generation 2 VMs, Linux Secure Boot)
- Deploying Active Directory with PowerShell: forest, OU, users, groups and a Kerberoastable service account
- Installing and licensing Splunk Enterprise on Ubuntu Server
- Forwarding Windows event logs with the Splunk Universal Forwarder (receiving port, `inputs.conf`)
- Enabling advanced audit policy and Sysmon to get detection-ready telemetry
- Verifying the log pipeline end to end with SPL

### Tools Used

- Hyper-V
- Windows Server 2022 (AD DS, DNS), Windows 11
- Ubuntu Server 22.04
- Splunk Enterprise, Splunk Universal Forwarder, Splunk Add-on for Microsoft Windows
- Sysmon (SwiftOnSecurity config), auditpol, PowerShell

## Lab Topology

| VM | OS | IP | Role |
|---|---|---|---|
| DC01 | Windows Server 2022 | 10.10.10.10 | Domain Controller, DNS (`lab.local`) |
| CLIENT01 | Windows 11 | 10.10.10.20 | Domain-joined workstation |
| SPLUNK01 | Ubuntu Server 22.04 | 10.10.10.30 | Splunk indexer + search head |

DC01 and CLIENT01 run the Universal Forwarder and send Security, System and Sysmon logs to SPLUNK01 on TCP 9997.

## Steps

#### 1. Hyper-V Network and VMs

Hyper-V Manager → Virtual Switch Manager → **Internal** switch `LAB-INTERNAL`, so lab traffic stays off the real network. Then three **Generation 2** VMs on that switch:

- **DC01:** 4 GB RAM, 2 vCPU, 60 GB disk
- **CLIENT01:** 4 GB RAM, 2 vCPU, 60 GB disk
- **SPLUNK01:** 6–8 GB RAM, 2 vCPU, 40 GB disk. Under Settings → Security keep Secure Boot on but switch the template to **Microsoft UEFI Certificate Authority**, otherwise Ubuntu does not boot on Gen 2.

#### 2. Domain Controller (DC01)

Static IP, rename, then promote to a new forest `lab.local`:

```powershell
Rename-Computer -NewName "DC01" -Restart
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Force:$true
```

Test objects: a `LabUsers` OU with 10 users, an `IT-Admins` group and a service account `svc-sql` with an SPN. The SPN makes it **Kerberoastable on purpose** for the attack simulation later.

```powershell
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"
1..10 | ForEach-Object {
  New-ADUser -Name "user$_" -SamAccountName "user$_" -UserPrincipalName "user$_@lab.local" `
    -Path "OU=LabUsers,DC=lab,DC=local" -Enabled $true `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
}
New-ADGroup -Name "IT-Admins" -GroupScope Global -Path "OU=LabUsers,DC=lab,DC=local"
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -UserPrincipalName "svc-sql@lab.local" `
  -Path "OU=LabUsers,DC=lab,DC=local" -Enabled $true `
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
setspn -A MSSQLSvc/dc01.lab.local:1433 LAB\svc-sql
```
<img width="1026" height="719" alt="b3-ad-users-groups" src="https://github.com/user-attachments/assets/96fd1719-85ab-4619-8d1f-8150373dcbbd" />

*Ref 1: LabUsers OU with test users, IT-Admins group and svc-sql*

#### 3. Windows 11 Client (CLIENT01)

Static IP `10.10.10.20/24` with DNS pointing to DC01, then join the domain and sign in as a domain user:

```powershell
Add-Computer -DomainName "lab.local" -Credential (Get-Credential) -Restart
```
<img width="1026" height="714" alt="c-client01-joined" src="https://github.com/user-attachments/assets/2b5a4165-a02a-4bb0-aae8-b1b4c5a816fc" />

*Ref 2: CLIENT01 in the Computers container on DC01*

<img width="1018" height="761" alt="c-domain-login" src="https://github.com/user-attachments/assets/953bde77-d03e-4991-aae2-ac6471e7ff5f" />

*Ref 3: Domain sign-in as LAB\user1*

#### 4. Ubuntu Server and Splunk Enterprise (SPLUNK01)

Ubuntu Server 22.04 with static IP `10.10.10.30/24` and OpenSSH. After the first boot, update and add the Hyper-V integration packages:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install linux-virtual linux-tools-virtual linux-cloud-tools-virtual -y
```

Install Splunk Enterprise from the `.deb` package and run it as a dedicated `splunk` user (running as root is deprecated):

```bash
sudo dpkg -i splunk-*-linux-2.6-amd64.deb
sudo useradd -m -s /bin/bash splunk
sudo chown -R splunk:splunk /opt/splunk
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start -user splunk
```

The web UI runs on `http://10.10.10.30:8000`. For the license I kept the **Enterprise Trial** (60 days) instead of switching to Free (see Notes).

<img width="1912" height="901" alt="e-splunk-home" src="https://github.com/user-attachments/assets/313ccb37-35ad-4f6b-b8b3-e41795d6771a" />

*Ref 4: Splunk Enterprise after first login*

#### 5. Universal Forwarder (DC01 and CLIENT01)

First enable receiving on Splunk: **Settings → Forwarding and receiving → Configure receiving → New Receiving Port → 9997**. Then install the Universal Forwarder `.msi` on both Windows hosts and set the receiving indexer to `10.10.10.30:9997`.

Inputs in `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Security]
disabled = 0
index = main

[WinEventLog://System]
disabled = 0
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
renderXml = true
```

Apply with `Restart-Service SplunkForwarder` and check the connection with `splunk.exe list forward-server`. It must show **Active forwards**.

<img width="1204" height="716" alt="f-uf-installed-dc01" src="https://github.com/user-attachments/assets/49a8ca8b-3f49-4936-add1-b7002e3af0f1" />

*Ref 5: Universal Forwarder installed on DC01*

#### 6. Windows Add-on for Splunk

Apps → Find More Apps → **Splunk Add-on for Microsoft Windows**. It provides the field extractions (`EventCode`, `Account_Name`, `Logon_Type`, …) used by searches and detections.

<img width="1912" height="914" alt="g-eventcode-4624" src="https://github.com/user-attachments/assets/9a8b6055-37ea-4aba-943c-54bdf4b8d5a2" />

*Ref 6: Successful logons (4624) from DC01 with extracted fields*

#### 7. Audit Policy (DC01)

Enable the subcategories that the detections will rely on:

```bat
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

#### 8. Sysmon (DC01 and CLIENT01)

Install Sysmon with the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) and confirm it is logging:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```
<img width="1365" height="710" alt="i-sysmon-dc01" src="https://github.com/user-attachments/assets/86302e19-9e4b-4421-99d0-f734e18b64e4" />

*Ref 7: Sysmon installed on DC01 and writing events*

#### 9. End-to-End Verification

Checkpoint all three VMs, then confirm the data is flowing from both hosts:

```spl
index=main host=DC01 EventCode=4624
index=main host=CLIENT01 source="*Sysmon*" EventCode=1
index=main host=DC01 EventCode=4720
```
<img width="1912" height="914" alt="j-eventcode-4720" src="https://github.com/user-attachments/assets/9b85a4c3-7c91-48bb-bed3-389cd96acf22" />

*Ref 8: User creation events (4720) from DC01 in Splunk*

#### 10. Notes and Good to Know

- **Enable receiving before installing the forwarders.** Without port 9997 open on Splunk, the forwarders install fine but no data arrives.
- **Forwarder Management is not a forwarder health check.** It only lists deployment-server clients, so it stays empty here. Use `splunk list forward-server` on the host and a `host=` search in Splunk.
- **Keep the Enterprise Trial.** Splunk Free has no alerting, no scheduled searches and no user authentication, and switching from Trial to Free cannot be undone. After 60 days a free Developer License is an option.
- **Gen 2 Linux VMs** need the *Microsoft UEFI Certificate Authority* Secure Boot template.
- Passwords in this README are throwaway values for an isolated lab network.

#### 11. Next Steps

- SPL detections and alerts (brute force, Kerberoasting, privileged group changes, suspicious processes)
- AD hardening with PingCastle and BloodHound
- Attack simulation (for example Kerberoasting `svc-sql`) to confirm the detections fire
