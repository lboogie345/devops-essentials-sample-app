<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Regenerate with: python scripts/stig/gen_control_docs.py --write
     Source: ansible/controls/disa-exports/RHEL8-V2R8-CAT_II.txt -->

# RHEL 8 CAT II control reference

**15 controls - 15 checks - 15 remediations.** One check and one remediation per control, quoted verbatim from the DISA export, joined to what this repository does about each one.

Counts are computed from `ansible/controls/disa-exports/RHEL8-V2R8-CAT_II.txt` at generation time. If your benchmark export contains a different number of controls, replace that file and regenerate - the totals above follow the source.

Implemented by the role: **15 of 15**.

## Index

| # | STIG ID | Group ID | Severity | Approach | Enforced by |
| ---: | --- | --- | --- | --- | --- |
| 1 | [`RHEL-08-010019`](#rhel-08-010019) | V-256973 | CAT II | assisted | `RHEL-08-010019.yml` |
| 2 | [`RHEL-08-010358`](#rhel-08-010358) | V-256974 | CAT II | automated | `RHEL-08-010358.yml` |
| 3 | [`RHEL-08-010379`](#rhel-08-010379) | V-251711 | CAT II | assisted | `RHEL-08-010379.yml` |
| 4 | [`RHEL-08-010385`](#rhel-08-010385) | V-251712 | CAT II | automated | `RHEL-08-010385.yml` |
| 5 | [`RHEL-08-010455`](#rhel-08-010455) | V-272484 | CAT II | gated | `RHEL-08-010455.yml` |
| 6 | [`RHEL-08-020035`](#rhel-08-020035) | V-257258 | CAT II | automated | `RHEL-08-020035.yml` |
| 7 | [`RHEL-08-020101`](#rhel-08-020101) | V-251713 | CAT II | assisted | `RHEL-08-020101.yml` |
| 8 | [`RHEL-08-020104`](#rhel-08-020104) | V-251716 | CAT II | automated | `RHEL-08-020104.yml` |
| 9 | [`RHEL-08-020360`](#rhel-08-020360) | V-279929 | CAT II | automated | `RHEL-08-020360.yml` |
| 10 | [`RHEL-08-030655`](#rhel-08-030655) | V-274877 | CAT II | automated | `RHEL-08-030655.yml` |
| 11 | [`RHEL-08-040221`](#rhel-08-040221) | V-284948 | CAT II | automated | `sysctl_network.yml` |
| 12 | [`RHEL-08-040222`](#rhel-08-040222) | V-284949 | CAT II | automated | `sysctl_network.yml` |
| 13 | [`RHEL-08-040287`](#rhel-08-040287) | V-284947 | CAT II | automated | `sysctl_network.yml` |
| 14 | [`RHEL-08-040321`](#rhel-08-040321) | V-251718 | CAT II | gated | `RHEL-08-040321.yml` |
| 15 | [`RHEL-08-040400`](#rhel-08-040400) | V-254520 | CAT II | gated | `RHEL-08-040400.yml` |

---

## RHEL-08-010019

**RHEL 8 must ensure cryptographic verification of vendor software packages.**

| | |
| --- | --- |
| Control | 1 of 15 |
| Group ID | V-256973 |
| Rule ID | `SV-256973r1017373` |
| Severity | CAT II |
| SRG | SRG-OS-000366-GPOS-00153 |
| CCI | CCI-001749, CCI-003992 |
| NIST 800-53 | CM-5 (3), CM-14 |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | low |
| Reboot required | False |

### Check

```text
Confirm Red Hat package-signing keys are installed on the system and verify their fingerprints match vendor values.

Note: For RHEL 8 software packages, Red Hat uses GPG keys labeled "release key 2" and "auxiliary key 2". The keys are defined in key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" by default.

List Red Hat GPG keys installed on the system:

     $ sudo rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey | grep -i "red hat"

     gpg(Red Hat, Inc. (release key 2) <security@redhat.com>)
     gpg(Red Hat, Inc. (auxiliary key) <security@redhat.com>)

If Red Hat GPG keys "release key 2" and "auxiliary key 2" are not installed, this is a finding.

Note: The "auxiliary key 2" appears as "auxiliary key" on a RHEL 8 system.

List key fingerprints of installed Red Hat GPG keys:

     $ sudo gpg -q --keyid-format short --with-fingerprint /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

If key file "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release" is missing, this is a finding.

Example output:

     pub   rsa4096/FD431D51 2009-10-22 [SC]
           Key fingerprint = 567E 347A D004 4ADE 55BA  8A5F 199E 2F91 FD43 1D51
     uid                   Red Hat, Inc. (release key 2) <security@redhat.com>
     pub   rsa4096/D4082792 2018-06-27 [SC]
           Key fingerprint = 6A6A A7C9 7C88 90AE C6AE  BFE2 F76F 66C3 D408 2792
     uid                   Red Hat, Inc. (auxiliary key) <security@redhat.com>
     sub   rsa4096/1B5584D3 2018-06-27 [E]
	   
Compare key fingerprints of installed Red Hat GPG keys with fingerprints listed for RHEL 8 on Red Hat "Product Signing Keys" webpage at https://access.redhat.com/security/team/key.

If key fingerprints do not match, this is a finding.
```

### Remediation (DISA fix text)

```text
Install Red Hat package-signing keys on the system and verify their fingerprints match vendor values.

Insert RHEL 8 installation disc or attach RHEL 8 installation image to the system. Mount the disc or image to make the contents accessible inside the system.

Assuming the mounted location is "/media/cdrom", use the following command to copy Red Hat GPG key file onto the system:

     $ sudo cp /media/cdrom/RPM-GPG-KEY-redhat-release /etc/pki/rpm-gpg/
	 
Import Red Hat GPG keys from key file into system keyring:

     $ sudo rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
	 
Using the steps listed in the Check Text, confirm the newly imported keys show as installed on the system and verify their fingerprints match vendor values.
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010019.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010019.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010019`.

> Keys cannot be manufactured by automation. The role restores the vendor key file from the redhat-release package, imports it, and asserts the fingerprints against hard-coded vendor values. A host with no key file and no package cache is reported for manual media-based remediation.

---

## RHEL-08-010358

**RHEL 8 must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel.**

| | |
| --- | --- |
| Control | 2 of 15 |
| Group ID | V-256974 |
| Rule ID | `SV-256974r1069321` |
| Severity | CAT II |
| SRG | SRG-OS-000363-GPOS-00150 |
| CCI | CCI-001744 |
| NIST 800-53 | CM-3 (5) |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | low |
| Reboot required | False |

### Check

```text
Verify that the operating system is configured to allow sending email notifications.

Note: The "mailx" package provides the "mail" command that is used to send email messages. The s-nail package is also suitable and may be used in place of mailx.

Verify that the "mailx" package is installed on the system:

     $ sudo yum list installed mailx

     mailx.x86_64     12.5-29.el8     @rhel-8-for-x86_64-baseos-rpm
	 
If "mailx" package is not installed, this is a finding.
```

### Remediation (DISA fix text)

```text
Install the "mailx" package on the system:

     $ sudo yum install mailx
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010358.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010358.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010358`.

> mailx or s-nail satisfies the check; the role accepts either.

---

## RHEL-08-010379

**RHEL 8 must specify the default "include" directory for the /etc/sudoers file.**

| | |
| --- | --- |
| Control | 3 of 15 |
| Group ID | V-251711 |
| Rule ID | `SV-251711r1017365` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Note: If the "include" and "includedir" directives are not present in the /etc/sudoers file, this requirement is not applicable.

Verify the operating system specifies only the default "include" directory for the /etc/sudoers file with the following command:

$ sudo grep include /etc/sudoers

#includedir /etc/sudoers.d

If the results are not "/etc/sudoers.d" or additional files or directories are specified, this is a finding.

Verify the operating system does not have nested "include" files or directories within the /etc/sudoers.d directory with the following command:

$ sudo grep -r include /etc/sudoers.d

If results are returned, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the /etc/sudoers file to only include the /etc/sudoers.d directory.

Edit the /etc/sudoers file with the following command:

$ sudo visudo

Add or modify the following line:
#includedir /etc/sudoers.d
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010379.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010379.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010379`.

> Enforced through visudo validation. Nested includes found under /etc/sudoers.d are reported, never deleted automatically - removing one can revoke the privilege path the automation itself depends on.

---

## RHEL-08-010385

**The RHEL 8 operating system must not be configured to bypass password requirements for privilege escalation.**

| | |
| --- | --- |
| Control | 4 of 15 |
| Group ID | V-251712 |
| Rule ID | `SV-251712r1050789` |
| Severity | CAT II |
| SRG | SRG-OS-000373-GPOS-00156 |
| CCI | CCI-002038, CCI-004895 |
| NIST 800-53 | IA-11, SC-11 b |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify the operating system is not be configured to bypass password requirements for privilege escalation.

Check the configuration of the "/etc/pam.d/sudo" file with the following command:

$ sudo grep pam_succeed_if /etc/pam.d/sudo

If any occurrences of "pam_succeed_if" is returned from the command, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the "/etc/ pam.d/sudo" file with the following command:
$ sudo vi /etc/pam.d/sudo

Remove any occurrences of "pam_succeed_if" in the file.
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010385.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010385.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010385`.

> Removing pam_succeed_if from /etc/pam.d/sudo makes sudo prompt for a password where it previously did not. Confirm no automation authenticates through a passwordless sudo that relies on this bypass before enabling.

---

## RHEL-08-010455

**RHEL 8 must elevate the SELinux context when an administrator calls the sudo command.**

| | |
| --- | --- |
| Control | 5 of 15 |
| Group ID | V-272484 |
| Rule ID | `SV-272484r1134875` |
| Severity | CAT II |
| SRG | SRG-OS-000445-GPOS-00199 |
| CCI | CCI-002235 |
| NIST 800-53 | AC-6 (10) |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Verify the operating system elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be run as root:

# grep -r sysadm_r /etc/sudoers /etc/sudoers.d
/etc/sudoers.d/admins:<username> ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

If conflicting results are returned, this is a finding.

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the operating system to elevate the SELinux context when an administrator calls the sudo command.

Edit a file in the "/etc/sudoers.d" directory with the following command:

$ sudo visudo -f /etc/sudoers.d/<customfile>

Use the following example to build the <customfile> in the /etc/sudoers.d directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of the sudo command:

{designated_group_or_user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

Remove any configurations that conflict with the above from the following locations:
 
/etc/sudoers
/etc/sudoers.d/
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010455.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010455.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010455`.

> Requires an org-defined admin group. Off by default: a wrong sudoers entry locks every administrator out of privilege escalation at once.

---

## RHEL-08-020035

**RHEL 8.7 and higher must terminate idle user sessions.**

| | |
| --- | --- |
| Control | 6 of 15 |
| Group ID | V-257258 |
| Rule ID | `SV-257258r1069328` |
| Severity | CAT II |
| SRG | SRG-OS-000163-GPOS-00072 |
| CCI | CCI-001133 |
| NIST 800-53 | SC-10 |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Note: This requirement applies to RHEL versions 8.7 and higher. If the system is not RHEL version 8.7 or newer, this requirement is not applicable.

Note: For cloud hosted systems where "ClientAliveInterval" (V-244525) is configured, this setting is not applicable.

Verify that RHEL 8 logs out sessions that are idle for 10 minutes with the following command:

$ sudo grep -i ^StopIdleSessionSec /etc/systemd/logind.conf

StopIdleSessionSec=600

If "StopIdleSessionSec" is not configured to "600" seconds, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to log out idle sessions after 10 minutes by editing the /etc/systemd/logind.conf file with the following line:

StopIdleSessionSec=600

The "logind" service must be restarted for the changes to take effect. To restart the "logind" service, run the following command:

$ sudo systemctl restart systemd-logind
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020035.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020035.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020035`.

> Not applicable below 8.7, and not applicable on cloud-hosted systems where ClientAliveInterval (V-244525) is configured. Both exclusions are wired to variables so the skip is recorded as Not_Applicable, not as a silent pass.

Applicability: RHEL >= 8.7.

---

## RHEL-08-020101

**RHEL 8 must ensure the password complexity module is enabled in the system-auth file.**

| | |
| --- | --- |
| Control | 7 of 15 |
| Group ID | V-251713 |
| Rule ID | `SV-251713r1017366` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Verify the operating system uses "pwquality" to enforce the password complexity rules. 

Check for the use of "pwquality" in the system-auth file with the following command:

     $ sudo cat /etc/pam.d/system-auth | grep pam_pwquality

     password requisite pam_pwquality.so

If the command does not return a line containing the value "pam_pwquality.so" as shown, or the line is commented out, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the operating system to use "pwquality" to enforce password complexity rules.

Add the following line to the "/etc/pam.d/system-auth" file (or modify the line to have the required value):

     password requisite pam_pwquality.so
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020101.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020101.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020101`.

> /etc/pam.d/system-auth is owned by authselect. Editing it in place is reverted by the next authselect apply and breaks `authselect check`. The role edits the custom authselect profile instead and re-applies it.

---

## RHEL-08-020104

**RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less.**

| | |
| --- | --- |
| Control | 8 of 15 |
| Group ID | V-251716 |
| Rule ID | `SV-251716r1069329` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | low |
| Reboot required | False |

### Check

```text
Note: This requirement applies to RHEL versions 8.4 or newer. If the system is RHEL below version 8.4, this requirement is not applicable.

Verify RHEL 8 is configured to limit the "pwquality" retry option to "3".

Check for the use of the retry option in the security directory with the following command:

$ grep -w retry /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf

retry = 3

If the value of "retry" is set to "0" or greater than "3", or is missing, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to limit the "pwquality" retry option to "3".

Add or update the following line in the "/etc/security/pwquality.conf" file or a file in the "/etc/security/pwquality.conf.d/" directory to contain the "retry" parameter:

retry = 3
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020104.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020104.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020104`.

Applicability: RHEL >= 8.4.

---

## RHEL-08-020360

**RHEL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.**

| | |
| --- | --- |
| Control | 9 of 15 |
| Group ID | V-279929 |
| Rule ID | `SV-279929r1156340` |
| Severity | CAT II |
| SRG | SRG-OS-000163-GPOS-00072 |
| CCI | CCI-001133 |
| NIST 800-53 | SC-10 |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify RHEL 8 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

$ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh

/etc/profile.d/tmout.sh:declare -xr TMOUT=600

If "TMOUT" is not set to "600" or less in a script located in the "/etc/'profile.d/ directory, is missing or is commented out, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to exit interactive command shell user sessions after 10 minutes of inactivity.

Add or edit the following line in "/etc/profile.d/tmout.sh":

#!/bin/bash

declare -xr TMOUT=600
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020360.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020360.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020360`.

---

## RHEL-08-030655

**RHEL 8 must audit any script or executable called by cron as root or by any privileged user.**

| | |
| --- | --- |
| Control | 10 of 15 |
| Group ID | V-274877 |
| Rule ID | `SV-274877r1155381` |
| Severity | CAT II |
| SRG | SRG-OS-000471-GPOS-00215 |
| CCI | CCI-000172 |
| NIST 800-53 | AU-12 c |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | low |
| Reboot required | conditional |

### Check

```text
Verify RHEL 8 is configured to audit the execution of any system call made by cron as root or as any privileged user.

$ sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands do not return the expected output, or the lines are commented out, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
-w /etc/cron.d/ -p wa -k cronjobs
-w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-030655.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-030655.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-030655`.

> If auditd is in immutable mode (-e 2) the new rules only take effect after a reboot. The role detects this and reports reboot_required rather than claiming compliance the running kernel does not have.

---

## RHEL-08-040221

**RHEL 8 must log IPv4 packets with impossible addresses.**

| | |
| --- | --- |
| Control | 11 of 15 |
| Group ID | V-284948 |
| Rule ID | `SV-284948r1208757` |
| Severity | CAT II |
| SRG | SRG-OS-000420-GPOS-00186 |
| CCI | CCI-002386 |
| NIST 800-53 | SC-5 |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | low |
| Reboot required | False |

### Check

```text
Verify RHEL 8 logs IPv4 martian packets.

Check the value of the "log_martians" variable with the following command:

$ sudo sysctl net.ipv4.conf.all.log_martians
net.ipv4.conf.all.log_martians = 1

If "net.ipv4.conf.all.log_martians" is not set to "1" or is missing, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to log martian packets on IPv4 interfaces.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_log_martians.conf

Add the following line to the file:

net.ipv4.conf.all.log_martians=1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml`](../ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040221`.

---

## RHEL-08-040222

**RHEL 8 must log IPv4 packets with impossible addresses by default.**

| | |
| --- | --- |
| Control | 12 of 15 |
| Group ID | V-284949 |
| Rule ID | `SV-284949r1208759` |
| Severity | CAT II |
| SRG | SRG-OS-000420-GPOS-00186 |
| CCI | CCI-002386 |
| NIST 800-53 | SC-5 |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | low |
| Reboot required | False |

### Check

```text
Verify RHEL 8 logs IPv4 martian packets by default.

Check the value of the "default.log_martians" variable with the following command:

$ sudo sysctl net.ipv4.conf.default.log_martians
net.ipv4.conf.default.log_martians = 1

If "net.ipv4.conf.default.log_martians" is not set to "1" or is missing, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to log martian packets on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_log_martians.conf

Add the following line to the file:

net.ipv4.conf.default.log_martians=1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml`](../ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040222`.

---

## RHEL-08-040287

**RHEL 8 must use a reverse-path filter for IPv4 network traffic, when possible, by default.**

| | |
| --- | --- |
| Control | 13 of 15 |
| Group ID | V-284947 |
| Rule ID | `SV-284947r1210519` |
| Severity | CAT II |
| SRG | SRG-OS-000420-GPOS-00186 |
| CCI | CCI-002385 |
| NIST 800-53 | SC-5, SC-5 a |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify RHEL 8 uses reverse path filtering on IPv4 interfaces.

Check the value of the "net.ipv4.conf.default.rp_filter" with the following command:

$ sudo sysctl net.ipv4.conf.default.rp_filter
net.ipv4.conf.default.rp_filter = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to use reverse path filtering on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_rp_filter.conf

Add the following line to the file:

net.ipv4.conf.default.rp_filter = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml`](../ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040287`.

> rp_filter must not be strict on asymmetric-routing hosts. The role sets the `default` scope only and leaves existing interfaces alone unless explicitly told otherwise.

---

## RHEL-08-040321

**The graphical display manager must not be the default target on RHEL 8 unless approved.**

| | |
| --- | --- |
| Control | 14 of 15 |
| Group ID | V-251718 |
| Rule ID | `SV-251718r1017371` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | medium |
| Reboot required | True |

### Check

```text
Verify that the system is configured to boot to the command line:

$ systemctl get-default
multi-user.target

If the system default target is not set to "multi-user.target" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding.
```

### Remediation (DISA fix text)

```text
Document the requirement for a graphical user interface with the ISSO or reinstall the operating system without the graphical user interface. If reinstallation is not feasible, then continue with the following procedure:

Open an SSH session and enter the following commands:

$ sudo systemctl set-default multi-user.target

A reboot is required for the changes to take effect.
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040321.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040321.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040321`.

> Hosts with an ISSO-documented GUI requirement are exempted by inventory variable, which produces a Not_Applicable with the approval reference recorded in the evidence artifact.

---

## RHEL-08-040400

**RHEL 8 must prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures.**

| | |
| --- | --- |
| Control | 15 of 15 |
| Group ID | V-254520 |
| Rule ID | `SV-254520r1069331` |
| Severity | CAT II |
| SRG | SRG-OS-000324-GPOS-00125 |
| CCI | CCI-002235 |
| NIST 800-53 | AC-6 (10) |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Verify the operating system prevents nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures. 
 
Obtain a list of authorized users (other than system administrator and guest accounts) for the system. 
 
Check the list against the system by using the following command: 
 
     $ sudo semanage login -l | more
 
     Login Name    SELinux User    MLS/MCS Range    Service

     __default__   user_u                 s0-s0:c0.c1023        *
     root                   unconfined_u  s0-s0:c0.c1023        *
     system_u        system_u           s0-s0:c0.c1023        *
     joe                     staff_u                s0-s0:c0.c1023        *
 
All administrators must be mapped to the "sysadm_u", "staff_u", or an appropriately tailored confined role as defined by the organization. 
 
All authorized nonadministrative users must be mapped to the "user_u" role. 
 
If they are not mapped in this way, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures. 
 
Use the following command to map a new user to the "sysadm_u" role: 
 
     $ sudo semanage login -a -s sysadm_u <username> 
 
Use the following command to map an existing user to the "sysadm_u" role: 
 
     $ sudo semanage login -m -s sysadm_u <username> 
 
Use the following command to map a new user to the "staff_u" role: 
 
     $ sudo semanage login -a -s staff_u <username> 
 
Use the following command to map an existing user to the "staff_u" role: 
 
     $ sudo semanage login -m -s staff_u <username> 
 
Use the following command to map a new user to the "user_u" role: 
 
     $ sudo  semanage login -a -s user_u <username> 
 
Use the following command to map an existing user to the "user_u" role: 
 
     $ sudo semanage login -m -s user_u <username>

Note: SELinux confined users mapped to sysadm_u are not allowed to log in to the system over SSH, by default. If this is a required function, it can be configured by setting the ssh_sysadm_login SELinux boolean to "on" with the following command:

     $ sudo setsebool -P ssh_sysadm_login on

This must be documented with the information system security officer (ISSO) as an operational requirement.
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040400.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040400.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040400`.

> SELinux login mappings are per-account org data, not a setting. Off by default. Mapping an admin to sysadm_u blocks their SSH login unless ssh_sysadm_login is set, which itself needs an ISSO-documented operational requirement.

---
