# Demo 01 — Basic stalkerware audit

A family member is worried that their shared Pixel 7 may have monitoring
software installed by an ex-partner. A forensic dump was extracted (offline,
with consent) into `evidence/`.

The dump contains the typical TRACKBLOCK artifacts:

- `manifest.json` — platform + device metadata
- `apps.json` — installed packages (note three sideloaded/hidden apps)
- `permissions.json` — per-package granted permissions
- `accessibility.json` — apps with Accessibility Service access
- `device_admins.json` — apps holding Device Administrator rights

## Run it

```sh
python -m trackblock audit demos/01-basic/evidence
python -m trackblock --format json audit demos/01-basic/evidence
```

## What you should see

TRACKBLOCK flags 7 findings:

- **TB-0007 (TheTruthSpy, high)** — the disguised package `com.systemservice`
  matches a known stalkerware family.
- **TB-0009 (KidsGuard, high)** — `com.clevguard.kidsguard` masquerading as
  "WiFi Helper".
- **TB-PERM (PermissionCluster, high)** — `com.systemservice` holds RECORD_AUDIO
  + CAMERA + LOCATION + SMS + CALL_LOG *and* has Accessibility + Device-Admin
  rights; `com.example.notes` is a hidden sideloaded app with an
  audio/SMS/contacts surveillance cluster.
- **TB-0015 (Sideload, medium)** — three hidden apps installed outside the
  Play Store.

The verdict is `suspicious` (risk score 100/100) and the process exits
non-zero (1), so the command can be used directly as a pass/fail gate in an
audit script. Add a `processes.json` with a Pegasus artifact (e.g.
`roleaboutd`) and the verdict escalates to `compromised`.
