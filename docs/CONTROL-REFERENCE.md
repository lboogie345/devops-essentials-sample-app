<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Regenerate with: python scripts/stig/gen_control_docs.py --write
     Sources: ansible/controls/disa-exports/RHEL8-V2R8-CAT_II-001.txt, ansible/controls/disa-exports/RHEL8-V2R8-CAT_II-002.txt -->

# RHEL 8 CAT II control reference

**29 controls - 29 checks - 29 remediations.** One check and one remediation per control, quoted verbatim from the DISA export, joined to what this repository does about each one.

Counts are computed at generation time from `ansible/controls/disa-exports/RHEL8-V2R8-CAT_II-001.txt`, `ansible/controls/disa-exports/RHEL8-V2R8-CAT_II-002.txt`. Add another export to that directory and regenerate; the totals follow the source. The full RHEL 8 V2R8 benchmark contains 314 CAT II rules, so this set is expected to grow.

Implemented by the role: **29 of 29**.

## Index

| # | STIG ID | Group ID | Severity | Approach | Enforced by |
| ---: | --- | --- | --- | --- | --- |
| 1 | [`RHEL-08-010019`](#rhel-08-010019) | V-256973 | CAT II | assisted | `RHEL-08-010019.yml` |
| 2 | [`RHEL-08-010090`](#rhel-08-010090) | V-230229 | CAT II | assisted | `RHEL-08-010090.yml` |
| 3 | [`RHEL-08-010358`](#rhel-08-010358) | V-256974 | CAT II | automated | `RHEL-08-010358.yml` |
| 4 | [`RHEL-08-010379`](#rhel-08-010379) | V-251711 | CAT II | assisted | `RHEL-08-010379.yml` |
| 5 | [`RHEL-08-010385`](#rhel-08-010385) | V-251712 | CAT II | automated | `RHEL-08-010385.yml` |
| 6 | [`RHEL-08-010400`](#rhel-08-010400) | V-230274 | CAT II | assisted | `RHEL-08-010400.yml` |
| 7 | [`RHEL-08-010455`](#rhel-08-010455) | V-272484 | CAT II | gated | `RHEL-08-010455.yml` |
| 8 | [`RHEL-08-010490`](#rhel-08-010490) | V-230287 | CAT II | automated | `RHEL-08-010490.yml` |
| 9 | [`RHEL-08-010590`](#rhel-08-010590) | V-230302 | CAT II | gated | `RHEL-08-010590.yml` |
| 10 | [`RHEL-08-010731`](#rhel-08-010731) | V-244531 | CAT II | assisted | `RHEL-08-010731.yml` |
| 11 | [`RHEL-08-010741`](#rhel-08-010741) | V-244532 | CAT II | assisted | `RHEL-08-010741.yml` |
| 12 | [`RHEL-08-020017`](#rhel-08-020017) | V-230339 | CAT II | automated | `RHEL-08-020017.yml` |
| 13 | [`RHEL-08-020035`](#rhel-08-020035) | V-257258 | CAT II | automated | `RHEL-08-020035.yml` |
| 14 | [`RHEL-08-020090`](#rhel-08-020090) | V-230355 | CAT II | gated | `RHEL-08-020090.yml` |
| 15 | [`RHEL-08-020101`](#rhel-08-020101) | V-251713 | CAT II | assisted | `RHEL-08-020101.yml` |
| 16 | [`RHEL-08-020104`](#rhel-08-020104) | V-251716 | CAT II | automated | `RHEL-08-020104.yml` |
| 17 | [`RHEL-08-020250`](#rhel-08-020250) | V-230372 | CAT II | gated | `RHEL-08-020250.yml` |
| 18 | [`RHEL-08-020320`](#rhel-08-020320) | V-230379 | CAT II | gated | `RHEL-08-020320.yml` |
| 19 | [`RHEL-08-020352`](#rhel-08-020352) | V-230384 | CAT II | assisted | `RHEL-08-020352.yml` |
| 20 | [`RHEL-08-020360`](#rhel-08-020360) | V-279929 | CAT II | automated | `RHEL-08-020360.yml` |
| 21 | [`RHEL-08-030655`](#rhel-08-030655) | V-274877 | CAT II | automated | `RHEL-08-030655.yml` |
| 22 | [`RHEL-08-040030`](#rhel-08-040030) | V-230500 | CAT II | manual | `RHEL-08-040030.yml` |
| 23 | [`RHEL-08-040137`](#rhel-08-040137) | V-244546 | CAT II | gated | `RHEL-08-040137.yml` |
| 24 | [`RHEL-08-040140`](#rhel-08-040140) | V-230524 | CAT II | gated | `RHEL-08-040140.yml` |
| 25 | [`RHEL-08-040221`](#rhel-08-040221) | V-284948 | CAT II | automated | `sysctl_network.yml` |
| 26 | [`RHEL-08-040222`](#rhel-08-040222) | V-284949 | CAT II | automated | `sysctl_network.yml` |
| 27 | [`RHEL-08-040287`](#rhel-08-040287) | V-284947 | CAT II | automated | `sysctl_network.yml` |
| 28 | [`RHEL-08-040321`](#rhel-08-040321) | V-251718 | CAT II | gated | `RHEL-08-040321.yml` |
| 29 | [`RHEL-08-040400`](#rhel-08-040400) | V-254520 | CAT II | gated | `RHEL-08-040400.yml` |

---

## RHEL-08-010019

**RHEL 8 must ensure cryptographic verification of vendor software packages.**

| | |
| --- | --- |
| Control | 1 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010019.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010019.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010019` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010019` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010019_allow_pkg_reinstall` | `true` |
| `stig_010019_enabled` | `true` |
| `stig_010019_expected_fingerprints` | `['567E347AD0044ADE55BA8A5F199E2F91FD431D51', '6A6AA7C97C8890AEC6AEBFE2F76F66C3D4082792']` |
| `stig_010019_keyfile` | `/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release` |
| `stig_audit_only` | `false` |

---

## RHEL-08-010090

**RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.**

| | |
| --- | --- |
| Control | 2 of 29 |
| Group ID | V-230229 |
| Rule ID | `SV-230229r1017048` |
| Severity | CAT II |
| SRG | SRG-OS-000066-GPOS-00034 |
| CCI | CCI-000185 |
| NIST 800-53 | IA-5 (2), IA-5 (2) (a), IA-5 (2) (b) (1) |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify RHEL 8 for PKI-based authentication has valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check that the system has a valid DoD root CA installed with the following command:

$ sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem

Certificate:
   Data:
      Version: 3 (0x2)
      Serial Number: 1 (0x1)
      Signature Algorithm: sha256WithRSAEncryption
      Issuer: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
      Validity
         Not Before: Mar 20 18:46:41 2012 GMT
         Not After   : Dec 30 18:46:41 2029 GMT
      Subject: C = US, O = U.S. Government, OU = DoD, OU = PKI, CN = DoD Root CA 3
      Subject Public Key Info:
         Public Key Algorithm: rsaEncryption

If the root ca file is not a DoD-issued certificate with a valid date and installed in the /etc/sssd/pki/sssd_auth_ca_db.pem location, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8, for PKI-based authentication, to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Obtain a valid copy of the DoD root CA file from the PKI CA certificate bundle at cyber.mil and copy into the following file:

/etc/sssd/pki/sssd_auth_ca_db.pem
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010090.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010090.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010090`.

> Automation must not fetch a trust anchor over the network. The role verifies the DoD root CA is present at /etc/sssd/pki/sssd_auth_ca_db.pem, issued by DoD and currently valid, and deploys it only from an organization-controlled source when one is configured.

Applicability: Not applicable where an approved alternate MFA method is used.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010090.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010090.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010090` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010090` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010090_ca_db` | `/etc/sssd/pki/sssd_auth_ca_db.pem` |
| `stig_010090_ca_source` | _(unset)_ |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |
| `stig_mfa_alternate` | `false` |
| `stig_mfa_alternate_ref` | _(unset)_ |

---

## RHEL-08-010358

**RHEL 8 must be configured to allow sending email notifications of unauthorized configuration changes to designated personnel.**

| | |
| --- | --- |
| Control | 3 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010358.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010358.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010358` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010358` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010358_enabled` | `true` |
| `stig_010358_package` | `mailx` |
| `stig_audit_only` | `false` |

---

## RHEL-08-010379

**RHEL 8 must specify the default "include" directory for the /etc/sudoers file.**

| | |
| --- | --- |
| Control | 4 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010379.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010379.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010379` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010379` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010379_enabled` | `true` |
| `stig_010379_remove_nested_includes` | `false` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-010385

**The RHEL 8 operating system must not be configured to bypass password requirements for privilege escalation.**

| | |
| --- | --- |
| Control | 5 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010385.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010385.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010385` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010385` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010385_enabled` | `true` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-010400

**RHEL 8 must implement certificate status checking for multifactor authentication.**

| | |
| --- | --- |
| Control | 6 of 29 |
| Group ID | V-230274 |
| Rule ID | `SV-230274r1017089` |
| Severity | CAT II |
| SRG | SRG-OS-000375-GPOS-00160 |
| CCI | CCI-001948, CCI-004046 |
| NIST 800-53 | IA-2 (11), IA-2 (6) (a) |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify the operating system implements certificate status checking for multifactor authentication.

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check to see if Online Certificate Status Protocol (OCSP) is enabled and using the proper digest value on the system with the following command:

$ sudo grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v "^#"

certificate_verification = ocsp_dgst=sha1

If the certificate_verification line is missing from the [sssd] section, or is missing "ocsp_dgst=sha1", ask the administrator to indicate what type of multifactor authentication is being utilized and how the system implements certificate status checking.  If there is no evidence of certificate status checking being used, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the operating system to implement certificate status checking for multifactor authentication.

Review the "/etc/sssd/sssd.conf" file to determine if the system is configured to prevent OCSP or certificate verification.

Add the following line to the [sssd] section of the "/etc/sssd/sssd.conf" file:

certificate_verification = ocsp_dgst=sha1

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010400.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010400.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010400`.

> Only meaningful where SSSD performs PKI authentication. Writing certificate_verification into an sssd.conf on a host that does not do PKI auth manufactures a compliance record for a control that is not in force, so the role acts only when sssd.conf already exists.

Applicability: Not applicable where an approved alternate MFA method is used.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010400.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010400.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010400` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010400` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010400_verification` | `ocsp_dgst=sha1` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |
| `stig_mfa_alternate` | `false` |
| `stig_mfa_alternate_ref` | _(unset)_ |

---

## RHEL-08-010455

**RHEL 8 must elevate the SELinux context when an administrator calls the sudo command.**

| | |
| --- | --- |
| Control | 7 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010455.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010455.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010455` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-010455` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010455_admin_group` | _(unset)_ |
| `stig_010455_enabled` | `false` |
| `stig_010455_sudoers_file` | `/etc/sudoers.d/stig_selinux_admins` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-010490

**The RHEL 8 SSH private host key files must have mode 0600 or less permissive.**

| | |
| --- | --- |
| Control | 8 of 29 |
| Group ID | V-230287 |
| Rule ID | `SV-230287r1208746` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | low |
| Reboot required | False |

### Check

```text
Verify the SSH private host key files have mode "0600" or less permissive with the following command:

$ sudo ls -l /etc/ssh/ssh_host*key
-rw------- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
-rw------- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
-rw------- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key

If any private host key file has a mode more permissive than "0600", this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the mode of SSH private host key files under "/etc/ssh" to "0600" with the following command:

$ sudo chmod 0600 /etc/ssh/ssh_host*key

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010490.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010490.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010490`.

> Applies to private host keys only. The matching .pub files must stay world-readable; tightening them breaks host key verification for every client.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010490.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010490.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010490` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010490` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010490_enabled` | `true` |
| `stig_010490_restart_sshd` | `true` |
| `stig_audit_only` | `false` |

---

## RHEL-08-010590

**RHEL 8 must prevent code from being executed on file systems that contain user home directories.**

| | |
| --- | --- |
| Control | 9 of 29 |
| Group ID | V-230302 |
| Rule ID | `SV-230302r1017112` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | high |
| Reboot required | conditional |

### Check

```text
Verify file systems that contain user home directories are mounted with the "noexec" option.

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding as the "noexec" option cannot be used on the "/" system.

Find the file system(s) that contain the user home directories with the following command:

$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}' /etc/passwd

smithj:1001: /home/smithj
robinst:1002: /home/robinst

Check the file systems that are mounted at boot time with the following command:

$ sudo more /etc/fstab

UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home ext4 rw,relatime,discard,data=ordered,nosuid,nodev,noexec 0 2

If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the "noexec" option set, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the "/etc/fstab" to use the "noexec" option on file systems that contain user home directories for interactive users.
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010590.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010590.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010590`.

> If home directories sit on / the check text makes this an automatic finding that cannot be remediated without repartitioning. A bad /etc/fstab edit renders a host unbootable, so the role validates the entry and remounts only when explicitly opted in.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010590.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010590.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010590` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-010590` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010590_enabled` | `false` |
| `stig_010590_remount` | `false` |
| `stig_audit_only` | `false` |

---

## RHEL-08-010731

**All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive.**

| | |
| --- | --- |
| Control | 10 of 29 |
| Group ID | V-244531 |
| Rule ID | `SV-244531r1017338` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of "0750".
Files that begin with a "." are excluded from this requirement.

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

$ sudo ls -lLR /home/smithj
-rwxr-x--- 1 smithj smithj 18 Mar 5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar 5 17:06 file2
-rw-r-x--- 1 smithj smithj 231 Mar 5 17:06 file3

If any files or directories are found with a mode more permissive than "0750", this is a finding.
```

### Remediation (DISA fix text)

```text
Set the mode on files and directories in the local interactive user home directory with the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.

$ sudo chmod 0750 /home/smithj/<file or directory>
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010731.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010731.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010731`.

> Forcing a literal 0750 would ADD the execute bit to data files. The role instead removes group-write and all other-access (g-w,o-rwx), which satisfies '0750 or less permissive' as a strict reduction. Dot-files are excluded per the check text.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010731.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010731.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010731` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010731` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010731_enabled` | `true` |
| `stig_audit_only` | `false` |

---

## RHEL-08-010741

**RHEL 8 must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.**

| | |
| --- | --- |
| Control | 11 of 29 |
| Group ID | V-244532 |
| Rule ID | `SV-244532r1101906` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify all files and directories in a local interactive user home directory are group-owned by a group that the user is a member.

Check the group owner of all files and directories in a local interactive user's home directory with the following command:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

$ sudo ls -lLR /<home directory>/<users home directory>/
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with a group owner different from the home directory user private group, check to see if the user is a member of that group with the following command:

$ sudo grep smithj /etc/group
sa:x:100:juan,shelley,bob,smithj 
smithj:x:521:smithj

If any files or directories are group owned by a group that the directory owner is not a member of verify that it is documented with the information system security officer (ISSO). If it is not, this is a finding.
```

### Remediation (DISA fix text)

```text
Change the group of a local interactive user's files and directories to a group that the interactive user is a member. To change the group owner of a local interactive user's files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.

$ sudo chgrp smithj /home/smithj/<file or directory>
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010741.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010741.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-010741`.

> Group ownership outside the owner's groups can be an ISSO-documented arrangement, so the role reports by default. Re-grouping to the owner's primary group is opt-in.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010741.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-010741.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-010741` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-010741` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_010741_enabled` | `true` |
| `stig_010741_fix` | `false` |
| `stig_audit_only` | `false` |

---

## RHEL-08-020017

**RHEL 8 must ensure account lockouts persist.**

| | |
| --- | --- |
| Control | 12 of 29 |
| Group ID | V-230339 |
| Rule ID | `SV-230339r1017151` |
| Severity | CAT II |
| SRG | SRG-OS-000021-GPOS-00005 |
| CCI | CCI-000044 |
| NIST 800-53 | AC-7 a |
| Approach | Automated - the role enforces this with no human decision required. |
| Residual risk | low |
| Reboot required | False |

### Check

```text
Note: This check applies to RHEL versions 8.2 or newer. If the system is RHEL version 8.0 or 8.1, this check is not applicable.

Verify the "/etc/security/faillock.conf" file is configured use a non-default faillock directory to ensure contents persist after reboot:

$ sudo grep 'dir =' /etc/security/faillock.conf

dir = /var/log/faillock

If the "dir" option is not set to a non-default documented tally log directory, is missing or commented out, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the operating system maintain the contents of the faillock directory after a reboot.

Add/Modify the "/etc/security/faillock.conf" file to match the following line:

dir = /var/log/faillock
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020017.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020017.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020017`.

> The default pam_faillock tally directory is cleared on boot, so lockouts do not survive a reboot. A non-default dir is the whole point of the control.

Applicability: RHEL >= 8.2.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020017.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020017.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020017` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-020017` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020017_dir` | `/var/log/faillock` |
| `stig_020017_enabled` | `true` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-020035

**RHEL 8.7 and higher must terminate idle user sessions.**

| | |
| --- | --- |
| Control | 13 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020035.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020035.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020035` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-020035` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020035_cloud_hosted` | `false` |
| `stig_020035_enabled` | `true` |
| `stig_020035_stop_idle_session_sec` | `600` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-020090

**RHEL 8 must map the authenticated identity to the user or group account for PKI-based authentication.**

| | |
| --- | --- |
| Control | 14 of 29 |
| Group ID | V-230355 |
| Rule ID | `SV-230355r1017168` |
| Severity | CAT II |
| SRG | SRG-OS-000068-GPOS-00036 |
| CCI | CCI-000187 |
| NIST 800-53 | IA-5 (2), IA-5 (2) (c), IA-5 (2) (a) (2) |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

$ sudo cat /etc/sssd/sssd.conf

[sssd]
config_file_version = 2
services = pam, sudo, ssh
domains = testing.test

[pam]
pam_cert_auth = True

[domain/testing.test]
id_provider = ldap

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the certmap section does not exist, ask the System Administrator to indicate how certificates are mapped to accounts. If there is no evidence of certificate mapping, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure the operating system to map the authenticated identity to the user or group account by adding or modifying the certmap section of the "/etc/sssd/sssd.conf file based on the following example:

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020090.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020090.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020090`.

> matchrule, maprule and the domain name are organizational PKI data. There is no safe default; a wrong certmap silently maps certificates to the wrong accounts.

Applicability: Not applicable where an approved alternate MFA method is used.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020090.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020090.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020090` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-020090` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020090_certmap` | _(unset)_ |
| `stig_020090_enabled` | `false` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |
| `stig_mfa_alternate` | `false` |
| `stig_mfa_alternate_ref` | _(unset)_ |

---

## RHEL-08-020101

**RHEL 8 must ensure the password complexity module is enabled in the system-auth file.**

| | |
| --- | --- |
| Control | 15 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020101.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020101.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020101` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-020101` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020101_allow_direct_pam_edit` | `true` |
| `stig_020101_authselect_profile` | `stig` |
| `stig_020101_enabled` | `true` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-020104

**RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less.**

| | |
| --- | --- |
| Control | 16 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020104.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020104.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020104` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-020104` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020104_enabled` | `true` |
| `stig_020104_retry` | `3` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-020250

**RHEL 8 must implement smart card logon for multifactor authentication for access to interactive accounts.**

| | |
| --- | --- |
| Control | 17 of 29 |
| Group ID | V-230372 |
| Rule ID | `SV-230372r1017184` |
| Severity | CAT II |
| SRG | SRG-OS-000105-GPOS-00052 |
| CCI | CCI-000765 |
| NIST 800-53 | IA-2 (1) |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Verify RHEL 8 uses multifactor authentication for local access to accounts.

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check that the "pam_cert_auth" setting is set to "true" in the "/etc/sssd/sssd.conf" file.

Check that the "try_cert_auth" or "require_cert_auth" options are configured in both "/etc/pam.d/system-auth" and "/etc/pam.d/smartcard-auth" files with the following command:

     $ sudo grep -ir cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf /etc/pam.d/*
     /etc/sssd/sssd.conf:pam_cert_auth = True
     /etc/pam.d/smartcard-auth:auth   sufficient   pam_sss.so try_cert_auth
     /etc/pam.d/system-auth:auth   [success=done authinfo_unavail=ignore ignore=ignore default=die]   pam_sss.so try_cert_auth

If "pam_cert_auth" is not set to "true" in "/etc/sssd/sssd.conf", this is a finding.

If "pam_sss.so" is not set to "try_cert_auth" or "require_cert_auth" in both the "/etc/pam.d/smartcard-auth" and "/etc/pam.d/system-auth" files, this is a finding.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to use multifactor authentication for local access to accounts.

Add or update the "pam_cert_auth" setting in the "/etc/sssd/sssd.conf" file to match the following line:

     [pam]
     pam_cert_auth = True

Add or update "pam_sss.so" with "try_cert_auth" or "require_cert_auth" in the "/etc/pam.d/system-auth" and "/etc/pam.d/smartcard-auth" files based on the following examples:

     /etc/pam.d/smartcard-auth:auth   sufficient   pam_sss.so try_cert_auth

     /etc/pam.d/system-auth:auth   [success=done authinfo_unavail=ignore ignore=ignore default=die]   pam_sss.so try_cert_auth

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

     $ sudo systemctl restart sssd.service
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020250.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020250.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020250`.

> Enforced through authselect (with-smartcard), never by editing the generated PAM files. Enabling it without working CAC infrastructure locks every interactive login out of the host at once.

Applicability: Not applicable where an approved alternate MFA method is used.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020250.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020250.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020250` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-020250` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020250_enabled` | `false` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |
| `stig_mfa_alternate` | `false` |
| `stig_mfa_alternate_ref` | _(unset)_ |

---

## RHEL-08-020320

**RHEL 8 must not have unnecessary accounts.**

| | |
| --- | --- |
| Control | 18 of 29 |
| Group ID | V-230379 |
| Rule ID | `SV-230379r1017190` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00227 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Verify that there are no unauthorized interactive user accounts with the following command:

$ less /etc/passwd

root:x:0:0:root:/root:/bin/bash
...
games:x:12:100:games:/usr/games:/sbin/nologin
scsaustin:x:1001:1001:scsaustin:/home/scsaustin:/bin/bash
djohnson:x:1002:1002:djohnson:/home/djohnson:/bin/bash

Interactive user account, generally will have a user identifier (UID) of 1000 or greater, a home directory in a specific partition, and an interactive shell.

Obtain the list of interactive user accounts authorized to be on the system from the system administrator or information system security officer (ISSO) and compare it to the list of local interactive user accounts on the system.

If there are unauthorized local user accounts on the system, this is a finding.
```

### Remediation (DISA fix text)

```text
Remove unauthorized local interactive user accounts with the following command where <unauthorized_user> is the unauthorized account:

$ sudo userdel <unauthorized_user>
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020320.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020320.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020320`.

> Requires the system's authorized-user list, which automation cannot hold. The role never runs userdel on its own initiative; it reports interactive accounts for comparison against that list.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020320.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020320.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020320` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-020320` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020320_enabled` | `false` |
| `stig_020320_protected_accounts` | `['root', "{{ ansible_user | default('ansible') }}"]` |
| `stig_020320_remove_accounts` | _(unset)_ |
| `stig_020320_remove_home` | `false` |
| `stig_audit_only` | `false` |
| `stig_interactive_uid_min` | `1000` |

---

## RHEL-08-020352

**RHEL 8 must set the umask value to 077 for all local interactive user accounts.**

| | |
| --- | --- |
| Control | 19 of 29 |
| Group ID | V-230384 |
| Rule ID | `SV-230384r1017193` |
| Severity | CAT II |
| SRG | SRG-OS-000480-GPOS-00228 |
| CCI | CCI-000366 |
| NIST 800-53 | CM-6 b |
| Approach | Assisted - the role converges what it safely can and reports the rest. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Verify that the default umask for all local interactive users is "077".

Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the "/home" directory.

$ sudo grep -ir ^umask /home | grep -v '.bash_history'

If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than "077", this is a finding.
```

### Remediation (DISA fix text)

```text
Remove the umask statement from all local interactive user's initialization files. 

If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the Information System Security Officer, but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account's environment variables.
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020352.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020352.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-020352`.

> The fix is removal of less-restrictive umask statements from user initialization files, which leaves the system default in force. Application accounts may carry a documented exception, so removal is opt-in.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020352.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020352.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `assisted` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020352` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-020352` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020352_enabled` | `true` |
| `stig_020352_remove` | `false` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-020360

**RHEL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.**

| | |
| --- | --- |
| Control | 20 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020360.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-020360.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-020360` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-020360` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_020360_enabled` | `true` |
| `stig_020360_file` | `/etc/profile.d/tmout.sh` |
| `stig_020360_reentrant_guard` | `false` |
| `stig_020360_tmout` | `600` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-030655

**RHEL 8 must audit any script or executable called by cron as root or by any privileged user.**

| | |
| --- | --- |
| Control | 21 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-030655.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-030655.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-030655` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-030655` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_030655_enabled` | `true` |
| `stig_030655_rules_file` | `/etc/audit/rules.d/50-stig-cronjobs.rules` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-040030

**RHEL 8 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.**

| | |
| --- | --- |
| Control | 22 of 29 |
| Group ID | V-230500 |
| Rule ID | `SV-230500r1101900` |
| Severity | CAT II |
| SRG | SRG-OS-000096-GPOS-00050 |
| CCI | CCI-000382 |
| NIST 800-53 | CM-7, CM-7 b |
| Approach | Manual - no automatable fix exists; the role gathers evidence for a human. |
| Residual risk | medium |
| Reboot required | False |

### Check

```text
Inspect the firewall configuration and running services to verify it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.

Check which services are currently active with the following command:

$ firewall-cmd --list-all-zones | grep -e "active" -e "services"

custom (active)
target: DROP
icmp-block-inversion: no
interfaces: ens33
sources: 
services: dhcpv6-client dns http https ldaps rpc-bind ssh
ports: 
masquerade: no
forward-ports: 
icmp-blocks: 
rich rules: 

Ask the system administrator (SA) for the site or program Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA). Verify the services allowed by the firewall match the PPSM CLSA. 

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.
```

### Remediation (DISA fix text)

```text
Update the host's firewall settings and/or running services to comply with the PPSM Component Local Service Assessment (CLSA) for the site or program and the PPSM CAL.
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040030.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040030.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040030`.

> The fix text contains no command. Compliance is defined by the site PPSM CLSA and the PPSM CAL, which are documents, not settings. The role captures firewalld zones, services and ports as evidence for the human comparison and always reports Open.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040030.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040030.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `manual` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040030` |
| Remediation template | **none** - no automatable fix |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Not applicable - no remediation template exists. |
| Evidence | `RHEL-08-040030` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040030_enabled` | `true` |

---

## RHEL-08-040137

**The RHEL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.**

| | |
| --- | --- |
| Control | 23 of 29 |
| Group ID | V-244546 |
| Rule ID | `SV-244546r1208752` |
| Severity | CAT II |
| SRG | SRG-OS-000368-GPOS-00154 |
| CCI | CCI-001764 |
| NIST 800-53 | CM-7 (2) |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Verify the RHEL 8 "fapolicyd" employs a deny-all, permit-by-exception policy.

Check that "fapolicyd" is in enforcement mode with the following command:

$ sudo grep permissive /etc/fapolicyd/fapolicyd.conf
permissive = 0

If "fapolicyd" is not running in enforcement mode, this is a finding.

Check that "fapolicyd" employs a deny-all policy on system mounts with the following commands:

$ sudo tail /etc/fapolicyd/compiled.rules
allow exe=/usr/bin/python3.7 : ftype=text/x-python
deny_audit perm=any pattern=ld_so : all
deny perm=any all : all

If "fapolicyd" is not running with a deny-all, permit-by-exception policy, this is a finding.

Note: "deny_log" or "deny_audit" options meet the security requirements. These options will generate higher volumes of logs.
```

### Remediation (DISA fix text)

```text
Configure RHEL 8 to employ a deny-all, permit-by-exception application allow listing policy with "fapolicyd".

With the "fapolicyd" installed and enabled, configure the daemon to function in permissive mode until the allow list is built correctly to avoid system lockout. Do this by editing the "/etc/fapolicyd/fapolicyd.conf" file with the following line:

permissive = 1

Build the allow list in a file within the "/etc/fapolicyd/rules.d" directory, ensuring the last rule implements a deny-all policy, such as "deny perm=any all : all".

Once it is determined the allow list is built correctly, set the "fapolicyd" to enforcing mode by editing the "permissive" line in the /etc/fapolicyd/fapolicyd.conf file.

permissive = 0
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040137.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040137.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040137`.

> The discussion warns that improper configuration renders the system nonfunctional, and that fapolicyd is not namespace-aware and breaks containers. The role will not set permissive=0 without an explicit opt-in confirming an allow list has been built and tested.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040137.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040137.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040137` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-040137` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040137_denyall_rule_file` | `/etc/fapolicyd/rules.d/99-stig-deny-all.rules` |
| `stig_040137_enabled` | `false` |
| `stig_040137_enforce` | `false` |
| `stig_audit_only` | `false` |
| `stig_backup` | `true` |

---

## RHEL-08-040140

**RHEL 8 must block unauthorized peripherals before establishing a connection.**

| | |
| --- | --- |
| Control | 24 of 29 |
| Group ID | V-230524 |
| Rule ID | `SV-230524r1155418` |
| Severity | CAT II |
| SRG | SRG-OS-000378-GPOS-00163 |
| CCI | CCI-001958 |
| NIST 800-53 | IA-3 |
| Approach | Gated - off by default; needs organization-supplied data before it runs. |
| Residual risk | high |
| Reboot required | False |

### Check

```text
Verify the USBGuard has a policy configured with the following command:

$ sudo usbguard list-rules

If the command does not return results or an error is returned, ask the SA to indicate how unauthorized peripherals are being blocked.
If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.

If the USBGuard package is not installed, ask the SA to indicate how unauthorized peripherals are being blocked.
If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.

If the system is a virtual machine with no virtual or physical USB peripherals attached, this is not a finding.
```

### Remediation (DISA fix text)

```text
Configure the operating system to enable the blocking of unauthorized peripherals with the following command:
This command must be run from a root shell and will create an allow list for any usb devices currently connect to the system.

# usbguard generate-policy > /etc/usbguard/rules.conf

Note: Enabling and starting usbguard without properly configuring it for an individual system will immediately prevent any access over a usb device such as a keyboard or mouse.

Restart usbguard service after creation or update of rules with the following command:

$ sudo systemctl restart usbguard
```

### How this repository remediates it

Enforced by [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040140.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040140.yml), runnable on its own with `ansible-playbook remediate.yml --tags RHEL-08-040140`.

> Starting usbguard without a generated policy immediately blocks USB input devices, including the keyboard on a physical console. Virtual machines with no USB peripherals attached are Not_Applicable per the check text.

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040140.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040140.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040140` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-040140` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040140_enabled` | `false` |
| `stig_040140_generate_policy` | `false` |
| `stig_audit_only` | `false` |

---

## RHEL-08-040221

**RHEL 8 must log IPv4 packets with impossible addresses.**

| | |
| --- | --- |
| Control | 25 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml`](../ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040221` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-040221` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040221_enabled` | `true` |
| `stig_audit_only` | `false` |
| `stig_sysctl_martians_file` | `/etc/sysctl.d/ipv4_log_martians.conf` |
| `stig_sysctl_report_conflicts` | `true` |
| `stig_sysctl_rpfilter_file` | `/etc/sysctl.d/ipv4_rp_filter.conf` |

---

## RHEL-08-040222

**RHEL 8 must log IPv4 packets with impossible addresses by default.**

| | |
| --- | --- |
| Control | 26 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml`](../ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `low` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040222` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-040222` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040222_enabled` | `true` |
| `stig_audit_only` | `false` |
| `stig_sysctl_martians_file` | `/etc/sysctl.d/ipv4_log_martians.conf` |
| `stig_sysctl_report_conflicts` | `true` |
| `stig_sysctl_rpfilter_file` | `/etc/sysctl.d/ipv4_rp_filter.conf` |

---

## RHEL-08-040287

**RHEL 8 must use a reverse-path filter for IPv4 network traffic, when possible, by default.**

| | |
| --- | --- |
| Control | 27 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml`](../ansible/roles/rhel8_stig_cat2/tasks/sysctl_network.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `automated` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040287` |
| Remediation template | `STIG CAT II - Remediate (Automated and Assisted)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | Tier approval node in the staged-rollout workflow. |
| Evidence | `RHEL-08-040287` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040287_apply_to_existing_interfaces` | `false` |
| `stig_040287_enabled` | `true` |
| `stig_audit_only` | `false` |
| `stig_sysctl_martians_file` | `/etc/sysctl.d/ipv4_log_martians.conf` |
| `stig_sysctl_report_conflicts` | `true` |
| `stig_sysctl_rpfilter_file` | `/etc/sysctl.d/ipv4_rp_filter.conf` |

---

## RHEL-08-040321

**The graphical display manager must not be the default target on RHEL 8 unless approved.**

| | |
| --- | --- |
| Control | 28 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040321.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040321.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `medium` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040321` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-040321` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040321_enabled` | `true` |
| `stig_040321_gui_approval_ref` | _(unset)_ |
| `stig_040321_gui_approved` | `false` |
| `stig_audit_only` | `false` |

---

## RHEL-08-040400

**RHEL 8 must prevent nonprivileged users from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures.**

| | |
| --- | --- |
| Control | 29 of 29 |
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

#### Mitigation path: GitHub

| | |
| --- | --- |
| Source of truth | [`ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040400.yml`](../ansible/roles/rhel8_stig_cat2/tasks/RHEL-08-040400.yml) |
| Required reviewers | `@your-org/platform-security @your-org/linux-engineering` (CODEOWNERS) |
| Merge gate | `stig-validate`: ansible-lint (production profile), yamllint, playbook syntax, evidence-schema contract, benchmark drift, AAP boundary tests |
| Risk classification | `gated` / residual risk `high` - reviewed in [`rhel8_cat2_controls.yml`](../ansible/controls/rhel8_cat2_controls.yml) |
| Change record | the merge commit; branch protection forbids force-push, so the history is the evidence |

#### Mitigation path: Ansible Automation Platform

| | |
| --- | --- |
| Project | `RHEL 8 STIG CAT II` (syncs this repo, revision updated on launch) |
| Job tag | `RHEL-08-040400` |
| Remediation template | `STIG CAT II - Remediate (Gated Control)` |
| Audit template | `STIG CAT II - Audit` (read-only, scheduled nightly) |
| Approval | **Dedicated approval node, one control per launch.** |
| Evidence | `RHEL-08-040400` entry in the per-host evidence document, collected by `STIG CAT II - Evidence Report` |

Tunables that steer this control, with their role defaults:

| Variable | Default |
| --- | --- |
| `stig_040400_enabled` | `false` |
| `stig_040400_logins` | _(unset)_ |
| `stig_040400_set_default_user_u` | `false` |
| `stig_040400_ssh_sysadm_login` | `false` |
| `stig_audit_only` | `false` |

---
