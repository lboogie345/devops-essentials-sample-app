## What changed

<!-- The control(s) touched, and what behaviour changes on a managed host. -->

## STIG controls affected

| STIG ID | Control | Change |
| --- | --- | --- |
|  |  |  |

## Blast radius

- [ ] I identified what breaks on a host if this change is wrong
- [ ] Nothing here can revoke administrative access (sudoers, PAM, SELinux user
      mappings) without an explicit, reviewed opt-in
- [ ] Changes that only take effect after a reboot are reported as such, not
      recorded as compliant

## Verification

- [ ] `ansible-lint` and `yamllint` pass
- [ ] `python -m pytest` passes
- [ ] Ran `--check --diff` against staging and attached the diff below
- [ ] Ran without `--check` against staging and re-ran the audit playbook to
      confirm the control converges to NotAFinding

<details>
<summary>Check-mode diff</summary>

```
paste here
```

</details>

## Change management

- Change record:
- Tier(s) to be applied:
- Risk acceptance (if any control is left Open):
